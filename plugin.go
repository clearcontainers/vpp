//
// Copyright (c) 2017 Intel Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package main

import (
	"bufio"
	"bytes"
	"encoding/gob"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os/exec"
	"sync"
	"time"

	"github.com/01org/ciao/ssntp/uuid"
	"github.com/boltdb/bolt"
	"github.com/docker/libnetwork/drivers/remote/api"
	ipamapi "github.com/docker/libnetwork/ipams/remote/api"
	"github.com/golang/glog"
	"github.com/gorilla/mux"
)

type epVal struct {
	IP      string
	vhostuserPort string //The dpdk vhost user port
	vppInterface   string
}

type nwVal struct {
	Bridge  string //The bridge on which the ports will be created
	Gateway net.IPNet
}

var intfCounter int

var epMap struct {
	sync.Mutex
	m map[string]*epVal
}

var nwMap struct {
	sync.Mutex
	m map[string]*nwVal
}

var brMap struct {
	sync.Mutex
	br_count int
	m map[string]int
}

var dbFile string
var db *bolt.DB

func init() {
	epMap.m = make(map[string]*epVal)
	nwMap.m = make(map[string]*nwVal)
	brMap.m = make(map[string]int)
	brMap.br_count = 1
	dbFile = "/tmp/dpdk_bolt.db"
}

//We should never see any errors in this function
func sendResponse(resp interface{}, w http.ResponseWriter) {
	rb, err := json.Marshal(resp)
	if err != nil {
		glog.Errorf("unable to marshal response %v", err)
	}
	glog.Infof("Sending response := %v, %v", resp, err)
	fmt.Fprintf(w, "%s", rb)
	return
}

func getBody(r *http.Request) ([]byte, error) {
	body, err := ioutil.ReadAll(r.Body)
	glog.Infof("URL [%s] Body [%s] Error [%v]", r.URL.Path[1:], string(body), err)
	return body, err
}

func handler(w http.ResponseWriter, r *http.Request) {
	body, _ := getBody(r)
	resp := api.Response{}
	resp.Err = "Unhandled API request " + string(r.URL.Path[1:]) + " " + string(body)
	sendResponse(resp, w)
}

func handlerPluginActivate(w http.ResponseWriter, r *http.Request) {
	_, _ = getBody(r)
	//TODO: Where is this encoding?
	resp := `{
    "Implements": ["NetworkDriver", "IpamDriver"]
}`
	fmt.Fprintf(w, "%s", resp)
}

func handlerGetCapabilities(w http.ResponseWriter, r *http.Request) {
	_, _ = getBody(r)
	resp := api.GetCapabilityResponse{Scope: "local"}
	sendResponse(resp, w)
}

func handlerCreateNetwork(w http.ResponseWriter, r *http.Request) {
	resp := api.CreateNetworkResponse{}

	body, err := getBody(r)
	if err != nil {
		resp.Err = "Error: " + err.Error()
		sendResponse(resp, w)
		return
	}

	req := api.CreateNetworkRequest{}
	if err := json.Unmarshal(body, &req); err != nil {
		resp.Err = "Error: " + err.Error()
		sendResponse(resp, w)
		return
	}

	//TODO: We can auto generate this, in the future. Just needs to be unique
	v, ok := req.Options["com.docker.network.generic"].(map[string]interface{})
	if !ok {
		resp.Err = "Error: network options incorrect or unspecified. Please provide bridge info"
		sendResponse(resp, w)
		return
	}

	bridge, ok := v["bridge"].(string)
	if !ok {
		resp.Err = "Error: network incorrect or unspecified. Please provide bridge info"
		sendResponse(resp, w)
		return
	}

	nwMap.Lock()
	defer nwMap.Unlock()

	//Record the docker network UUID to SDN bridge mapping
	//This has to survive a plugin crash/restart and needs to be persisted
	nwMap.m[req.NetworkID] = &nwVal{
		Bridge:  bridge,
		Gateway: *req.IPv4Data[0].Gateway,
	}

	if err := dbAdd("nwMap", req.NetworkID, nwMap.m[req.NetworkID]); err != nil {
		glog.Errorf("Unable to update db %v", err)
	}

	// For VPP, we are connecting endpoints via a bridge which requires
	// a unique integer ID.
	brMap.Lock()
	brMap.m[req.NetworkID] = brMap.br_count
	brMap.br_count = brMap.br_count + 1
	if err := dbAdd("brMap", req.NetworkID, brMap.m[req.NetworkID]); err != nil {
		glog.Errorf("Unable to update db %v", err)
	}
	brMap.Unlock()

	sendResponse(resp, w)
}

func handlerDeleteNetwork(w http.ResponseWriter, r *http.Request) {
	resp := api.DeleteNetworkResponse{}

	body, err := getBody(r)
	if err != nil {
		resp.Err = "Error: " + err.Error()
		sendResponse(resp, w)
		return
	}

	req := api.DeleteNetworkRequest{}
	if err = json.Unmarshal(body, &req); err != nil {
		resp.Err = "Error: " + err.Error()
		sendResponse(resp, w)
		return
	}

	glog.Infof("Delete Network := %v", req.NetworkID)

	nwMap.Lock()
	defer nwMap.Unlock()

	bridge := nwMap.m[req.NetworkID].Bridge
	delete(nwMap.m, req.NetworkID)
	if err := dbDelete("nwMap", req.NetworkID); err != nil {
		glog.Errorf("Unable to update db %v %v", err, bridge)
	}

	brMap.Lock()
	delete(brMap.m, req.NetworkID)
	if err := dbDelete("brMap", req.NetworkID); err != nil {
		glog.Errorf("Unable to update db %v %v", err, bridge)
	}
	brMap.Unlock()

	sendResponse(resp, w)
	return
}

func handlerEndpointOperInfof(w http.ResponseWriter, r *http.Request) {
	resp := api.EndpointInfoResponse{}
	body, err := getBody(r)

	if err != nil {
		resp.Err = "Error: " + err.Error()
		sendResponse(resp, w)
		return
	}

	req := api.EndpointInfoRequest{}
	err = json.Unmarshal(body, &req)

	if err != nil {
		resp.Err = "Error: " + err.Error()
		sendResponse(resp, w)
		return
	}

	sendResponse(resp, w)
}

func handlerCreateEndpoint(w http.ResponseWriter, r *http.Request) {
	resp := api.CreateEndpointResponse{}

	body, err := getBody(r)
	if err != nil {
		resp.Err = "Error: " + err.Error()
		sendResponse(resp, w)
		return
	}

	req := api.CreateEndpointRequest{}
	if err = json.Unmarshal(body, &req); err != nil {
		resp.Err = "Error: " + err.Error()
		sendResponse(resp, w)
		return
	}

	if req.Interface.Address == "" {
		resp.Err = "Error: IP Address parameter not provided in docker run"
		sendResponse(resp, w)
		return
	}

	ip, _, err := net.ParseCIDR(req.Interface.Address)
	if err != nil {
		resp.Err = "Error: Invalid IP Address " + err.Error()
		sendResponse(resp, w)
		return
	}

	nwMap.Lock()
	bridge := nwMap.m[req.NetworkID].Bridge
	nwMap.Unlock()

	if bridge == "" {
		resp.Err = "Error: incompatible network"
		sendResponse(resp, w)
		return
	}

	nwMap.Lock()
	defer nwMap.Unlock()

	epMap.Lock()
	defer epMap.Unlock()

	brMap.Lock()
	defer brMap.Unlock()

	//Generate a unique vhost-user port name
	vhost_port := fmt.Sprintf("v_%s", ip)

	//Generate VPP-dpdk vhost-user interface:
	cmd := "vppctl"
	args := []string{"create", "vhost", "socket", fmt.Sprintf("/tmp/%s", vhost_port), "server"}
	bifc, err := exec.Command(cmd, args...).Output()
	if err != nil {
		glog.Infof("ERROR: [%v] [%v] [%v] ", cmd, args, err)
		resp.Err = fmt.Sprintf("Error EndPointCreate: [%v] [%v] [%v]",
			cmd, args, err)
		sendResponse(resp, w)
		return
	}

	ifcb, _, err := bufio.NewReader(bytes.NewReader(bifc)).ReadLine()
	ifc := string(ifcb)

	glog.Infof("Created vhost-user interface %v %v", ifc, err)

	//Set Interface state to up
	cmd = "vppctl"
	args = []string{"set", "interface", "state", ifc, "up"}
	if err := exec.Command(cmd, args...).Run(); err != nil {
		resp.Err = fmt.Sprintf("Error EndPointCreate: [%v] [%v] [%v]",
			cmd, args, err)
		sendResponse(resp, w)
		return
	}

	//Attach VPP vhost-user interface to VPP L2 Bridge Domain
	//TODO: Need to create a unique bridge domain ID per network
	cmd = "vppctl"
	args = []string{"set", "interface", "l2", "bridge", ifc, fmt.Sprint(brMap.m[req.NetworkID])}
	if err := exec.Command(cmd, args...).Run(); err != nil {
		resp.Err = fmt.Sprintf("Error EndPointCreate: [%v] [%v] [%v]",
			cmd, args, err)
		sendResponse(resp, w)
		return
	}



	/* Setup the dummy interface corresponding to the dpdk port
	 * This is done so that docker CNM will program the IP Address
	 * and other properties on this Interface
	 * This dummy interface will be discovered by clear containers
	 * which then maps the actual vhost-user port to the VM
	 * This is needed today as docker does not pass any information
	 * from the network plugin to the runtime
	 */
	cmd = "ip"
	args = []string{"link", "add", vhost_port, "type", "dummy"}
	if err := exec.Command(cmd, args...).Run(); err != nil {
		resp.Err = fmt.Sprintf("Error EndPointCreate: [%v] [%v] [%v]",
			cmd, args, err)
		sendResponse(resp, w)
		return
	}

	glog.Infof("Setup dummy port %v %v ", cmd, args)

	epMap.m[req.EndpointID] = &epVal{
		IP:        req.Interface.Address,
		vhostuserPort:	vhost_port,
		vppInterface:	ifc,
	}

	if err := dbAdd("epMap", req.EndpointID, epMap.m[req.EndpointID]); err != nil {
		glog.Errorf("Unable to update db %v %v", err, ip)
	}

	sendResponse(resp, w)
}

func handlerDeleteEndpoint(w http.ResponseWriter, r *http.Request) {
	resp := api.DeleteEndpointResponse{}

	body, err := getBody(r)
	if err != nil {
		resp.Err = "Error: " + err.Error()
		sendResponse(resp, w)
		return
	}

	req := api.DeleteEndpointRequest{}
	if err = json.Unmarshal(body, &req); err != nil {
		resp.Err = "Error: " + err.Error()
		sendResponse(resp, w)
		return
	}

	epMap.Lock()
	nwMap.Lock()

	m := epMap.m[req.EndpointID]
	vhost_port := m.vhostuserPort
	vpp_interface := m.vppInterface

	delete(epMap.m, req.EndpointID)
	if err := dbDelete("epMap", req.EndpointID); err != nil {
		glog.Errorf("Unable to update db %v %v", err, m)
	}
	nwMap.Unlock()
	epMap.Unlock()

	//put interface into down state
	cmd := "vppctl"
	args := []string{"set", "interface", "state", vpp_interface, "down"}
	if err := exec.Command(cmd, args...).Run(); err != nil {
		resp.Err = fmt.Sprintf("Error DeleteEndpoint: [%v] [%v] [%v]",
			cmd, args, err)
		sendResponse(resp, w)
		return
	}

	//delete vhost interface
	cmd = "vppctl"
	args = []string{"delete", "vhost-user", vpp_interface}
	if err := exec.Command(cmd, args...).Run(); err != nil {
		resp.Err = fmt.Sprintf("Error DeleteEndpoint: [%v] [%v] [%v]",
			cmd, args, err)
		sendResponse(resp, w)
		return
	}

	//delete dummy port
	cmd = "ip"
	args = []string{"link", "del", vhost_port}
	if err := exec.Command(cmd, args...).Run(); err != nil {
		resp.Err = fmt.Sprintf("Error EndPointCreate: [%v] [%v] [%v]",
			cmd, args, err)
		sendResponse(resp, w)
		return
	}

	glog.Infof("Deleted dummy port %v %v ", cmd, args)

	sendResponse(resp, w)
}

func handlerJoin(w http.ResponseWriter, r *http.Request) {
	resp := api.JoinResponse{}

	body, err := getBody(r)
	if err != nil {
		resp.Err = "Error: " + err.Error()
		sendResponse(resp, w)
		return
	}

	req := api.JoinRequest{}
	if err := json.Unmarshal(body, &req); err != nil {
		resp.Err = "Error: " + err.Error()
		sendResponse(resp, w)
		return
	}

	nwMap.Lock()
	epMap.Lock()
	nm := nwMap.m[req.NetworkID]
	em := epMap.m[req.EndpointID]
	nwMap.Unlock()
	epMap.Unlock()

	resp.Gateway = nm.Gateway.IP.String()
	resp.InterfaceName = &api.InterfaceName{
		SrcName:   em.vhostuserPort,
		DstPrefix: "eth",
	}
	glog.Infof("Join Response %v %v", resp, em.vhostuserPort)
	sendResponse(resp, w)
}

func handlerLeave(w http.ResponseWriter, r *http.Request) {
	resp := api.LeaveResponse{}

	body, err := getBody(r)
	if err != nil {
		resp.Err = "Error: " + err.Error()
		sendResponse(resp, w)
		return
	}

	req := api.LeaveRequest{}
	if err := json.Unmarshal(body, &req); err != nil {
		resp.Err = "Error: " + err.Error()
		sendResponse(resp, w)
		return
	}

	sendResponse(resp, w)
}

func handlerDiscoverNew(w http.ResponseWriter, r *http.Request) {
	resp := api.DiscoveryResponse{}

	body, err := getBody(r)
	if err != nil {
		resp.Err = "Error: " + err.Error()
		sendResponse(resp, w)
		return
	}

	req := api.DiscoveryNotification{}
	if err := json.Unmarshal(body, &req); err != nil {
		resp.Err = "Error: " + err.Error()
		sendResponse(resp, w)
		return
	}

	sendResponse(resp, w)
}

func handlerDiscoverDelete(w http.ResponseWriter, r *http.Request) {
	resp := api.DiscoveryResponse{}

	body, err := getBody(r)
	if err != nil {
		resp.Err = "Error: " + err.Error()
		sendResponse(resp, w)
		return
	}

	req := api.DiscoveryNotification{}
	if err := json.Unmarshal(body, &req); err != nil {
		resp.Err = "Error: " + err.Error()
		sendResponse(resp, w)
		return
	}

	sendResponse(resp, w)
}

func handlerExternalConnectivity(w http.ResponseWriter, r *http.Request) {
	resp := api.ProgramExternalConnectivityResponse{}

	body, err := getBody(r)
	if err != nil {
		resp.Err = "Error: " + err.Error()
		sendResponse(resp, w)
		return
	}

	req := api.ProgramExternalConnectivityRequest{}
	if err := json.Unmarshal(body, &req); err != nil {
		resp.Err = "Error: " + err.Error()
		sendResponse(resp, w)
		return
	}

	sendResponse(resp, w)
}

func handlerRevokeExternalConnectivity(w http.ResponseWriter, r *http.Request) {
	resp := api.RevokeExternalConnectivityResponse{}

	body, err := getBody(r)
	if err != nil {
		resp.Err = "Error: " + err.Error()
		sendResponse(resp, w)
		return
	}

	req := api.RevokeExternalConnectivityResponse{}
	if err := json.Unmarshal(body, &req); err != nil {
		resp.Err = "Error: " + err.Error()
		sendResponse(resp, w)
		return
	}

	sendResponse(resp, w)
}

func ipamGetCapabilities(w http.ResponseWriter, r *http.Request) {
	if _, err := getBody(r); err != nil {
		glog.Infof("ipamGetCapabilities: unable to get request body [%v]", err)
	}
	resp := ipamapi.GetCapabilityResponse{RequiresMACAddress: true}
	sendResponse(resp, w)
}

func ipamGetDefaultAddressSpaces(w http.ResponseWriter, r *http.Request) {
	resp := ipamapi.GetAddressSpacesResponse{}
	if _, err := getBody(r); err != nil {
		glog.Infof("ipamGetDefaultAddressSpaces: unable to get request body [%v]", err)
	}

	resp.GlobalDefaultAddressSpace = ""
	resp.LocalDefaultAddressSpace = ""
	sendResponse(resp, w)
}

func ipamRequestPool(w http.ResponseWriter, r *http.Request) {
	resp := ipamapi.RequestPoolResponse{}

	body, err := getBody(r)
	if err != nil {
		resp.Error = "Error: " + err.Error()
		sendResponse(resp, w)
		return
	}

	req := ipamapi.RequestPoolRequest{}
	if err := json.Unmarshal(body, &req); err != nil {
		resp.Error = "Error: " + err.Error()
		sendResponse(resp, w)
		return
	}

	resp.PoolID = uuid.Generate().String()
	resp.Pool = req.Pool
	sendResponse(resp, w)
}

func ipamReleasePool(w http.ResponseWriter, r *http.Request) {
	resp := ipamapi.ReleasePoolResponse{}

	body, err := getBody(r)
	if err != nil {
		resp.Error = "Error: " + err.Error()
		sendResponse(resp, w)
		return
	}

	req := ipamapi.ReleasePoolRequest{}
	if err := json.Unmarshal(body, &req); err != nil {
		resp.Error = "Error: " + err.Error()
		sendResponse(resp, w)
		return
	}

	sendResponse(resp, w)
}

func ipamRequestAddress(w http.ResponseWriter, r *http.Request) {
	resp := ipamapi.RequestAddressResponse{}

	body, err := getBody(r)
	if err != nil {
		resp.Error = "Error: " + err.Error()
		sendResponse(resp, w)
		return
	}

	req := ipamapi.RequestAddressRequest{}
	if err := json.Unmarshal(body, &req); err != nil {
		resp.Error = "Error: " + err.Error()
		sendResponse(resp, w)
		return
	}

	//TODO: Should come from the subnet mask for the subnet
	if req.Address != "" {
		resp.Address = req.Address + "/24"
	} else {
		resp.Error = "Error: Request does not have IP address. Specify using --ip"
	}
	sendResponse(resp, w)
}

func ipamReleaseAddress(w http.ResponseWriter, r *http.Request) {
	resp := ipamapi.ReleaseAddressResponse{}

	body, err := getBody(r)
	if err != nil {
		resp.Error = "Error: " + err.Error()
		sendResponse(resp, w)
		return
	}

	req := ipamapi.ReleaseAddressRequest{}
	if err := json.Unmarshal(body, &req); err != nil {
		resp.Error = "Error: " + err.Error()
		sendResponse(resp, w)
		return
	}

	sendResponse(resp, w)
}

func dbTableInit(tables []string) (err error) {

	glog.Infof("dbInit Tables := %v", tables)
	for i, v := range tables {
		glog.Infof("table[%v] := %v, %v", i, v, []byte(v))
	}

	err = db.Update(func(tx *bolt.Tx) error {
		for _, table := range tables {
			_, err := tx.CreateBucketIfNotExists([]byte(table))
			if err != nil {
				return fmt.Errorf("Bucket creation error: %v %v", table, err)
			}
		}
		return nil
	})

	if err != nil {
		glog.Errorf("Table creation error %v", err)
	}

	return err
}

func dbAdd(table string, key string, value interface{}) (err error) {

	err = db.Update(func(tx *bolt.Tx) error {
		var v bytes.Buffer

		if err := gob.NewEncoder(&v).Encode(value); err != nil {
			glog.Errorf("Encode Error: %v %v", err, value)
			return err
		}

		bucket := tx.Bucket([]byte(table))
		if bucket == nil {
			return fmt.Errorf("Bucket %v not found", table)
		}

		err = bucket.Put([]byte(key), v.Bytes())
		if err != nil {
			return fmt.Errorf("Key Store error: %v %v %v %v", table, key, value, err)
		}
		return nil
	})

	return err
}

func dbDelete(table string, key string) (err error) {

	err = db.Update(func(tx *bolt.Tx) error {

		bucket := tx.Bucket([]byte(table))
		if bucket == nil {
			return fmt.Errorf("Bucket %v not found", table)
		}

		err = bucket.Delete([]byte(key))
		if err != nil {
			return fmt.Errorf("Key Delete error: %v %v ", key, err)
		}
		return nil
	})

	return err
}

func dbGet(table string, key string) (value interface{}, err error) {

	err = db.View(func(tx *bolt.Tx) error {

		bucket := tx.Bucket([]byte(table))
		if bucket == nil {
			return fmt.Errorf("Bucket %v not found", table)
		}

		val := bucket.Get([]byte(key))
		if val == nil {
			return nil
		}

		v := bytes.NewReader(val)
		if err := gob.NewDecoder(v).Decode(value); err != nil {
			glog.Errorf("Decode Error: %v %v %v", table, key, err)
			return err
		}

		return nil
	})

	return value, err
}

func initDb() error {

	options := bolt.Options{
		Timeout: 3 * time.Second,
	}

	var err error
	db, err = bolt.Open(dbFile, 0644, &options)
	if err != nil {
		return fmt.Errorf("dbInit failed %v", err)
	}

	tables := []string{"global", "nwMap", "epMap", "brMap"}
	if err := dbTableInit(tables); err != nil {
		return fmt.Errorf("dbInit failed %v", err)
	}

	c, err := dbGet("global", "counter")
	if err != nil {
		glog.Errorf("dbGet failed %v", err)
		intfCounter = 100
	} else {
		var ok bool
		intfCounter, ok = c.(int)
		if !ok {
			intfCounter = 100
		}
	}

	err = db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("nwMap"))

		err := b.ForEach(func(k, v []byte) error {
			vr := bytes.NewReader(v)
			nVal := &nwVal{}
			if err := gob.NewDecoder(vr).Decode(nVal); err != nil {
				return fmt.Errorf("Decode Error: %v %v %v", string(k), string(v), err)
			}
			nwMap.m[string(k)] = nVal
			glog.Infof("nwMap key=%v, value=%v\n", string(k), nVal)
			return nil
		})
		return err
	})

	if err != nil {
		return err
	}

	err = db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("epMap"))

		err := b.ForEach(func(k, v []byte) error {
			vr := bytes.NewReader(v)
			eVal := &epVal{}
			if err := gob.NewDecoder(vr).Decode(eVal); err != nil {
				return fmt.Errorf("Decode Error: %v %v %v", string(k), string(v), err)
			}
			epMap.m[string(k)] = eVal
			glog.Infof("epMap key=%v, value=%v\n", string(k), eVal)
			return nil
		})
		return err
	})

	if err != nil {
		return err
	}

	err = db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("brMap"))

		err := b.ForEach(func(k, v []byte) error {
			vr := bytes.NewReader(v)
			brVal := 0
			if err := gob.NewDecoder(vr).Decode(&brVal); err != nil {
				return fmt.Errorf("Decode Error: %v %v %v", string(k), string(v), err)
			}
			brMap.m[string(k)] = brVal
			glog.Infof("brMap key=%v, value=%v\n", string(k), brVal)
			return nil
		})
		return err
	})

	return err
}

func main() {
	flag.Parse()

	if err := initDb(); err != nil {
		glog.Fatalf("db init failed, quitting [%v]", err)
	}
	defer func() {
		err := db.Close()
		glog.Errorf("unable to close database [%v]", err)
	}()

	r := mux.NewRouter()
	r.HandleFunc("/Plugin.Activate", handlerPluginActivate)
	r.HandleFunc("/NetworkDriver.GetCapabilities", handlerGetCapabilities)
	r.HandleFunc("/NetworkDriver.CreateNetwork", handlerCreateNetwork)
	r.HandleFunc("/NetworkDriver.DeleteNetwork", handlerDeleteNetwork)
	r.HandleFunc("/NetworkDriver.CreateEndpoint", handlerCreateEndpoint)
	r.HandleFunc("/NetworkDriver.DeleteEndpoint", handlerDeleteEndpoint)
	r.HandleFunc("/NetworkDriver.EndpointOperInfo", handlerEndpointOperInfof)
	r.HandleFunc("/NetworkDriver.Join", handlerJoin)
	r.HandleFunc("/NetworkDriver.Leave", handlerLeave)
	r.HandleFunc("/NetworkDriver.DiscoverNew", handlerDiscoverNew)
	r.HandleFunc("/NetworkDriver.DiscoverDelete", handlerDiscoverDelete)
	r.HandleFunc("/NetworkDriver.ProgramExternalConnectivity", handlerExternalConnectivity)
	r.HandleFunc("/NetworkDriver.RevokeExternalConnectivity", handlerRevokeExternalConnectivity)

	r.HandleFunc("/IpamDriver.GetCapabilities", ipamGetCapabilities)
	r.HandleFunc("/IpamDriver.GetDefaultAddressSpaces", ipamGetDefaultAddressSpaces)
	r.HandleFunc("/IpamDriver.RequestPool", ipamRequestPool)
	r.HandleFunc("/IpamDriver.ReleasePool", ipamReleasePool)
	r.HandleFunc("/IpamDriver.RequestAddress", ipamRequestAddress)

	r.HandleFunc("/", handler)
	err := http.ListenAndServe("127.0.0.1:9075", r)
	if err != nil {
		glog.Errorf("docker plugin http server failed, [%v]", err)
	}
}
