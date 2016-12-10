# cc_vpp

This is simple standalone Docker Plugin implementation to demonstrate Clear Containers with VPP.

For more details about Clear Containers
https://github.com/01org/cc-oci-runtime
https://clearlinux.org/clear-containers

For more information about VPP
https://wiki.fd.io/view/VPP

This example demonstrates the VPP example with some minor modifications.
- The default network is no longer created
- Some of the IP and namespace ids have been modified

![alt tag](https://wiki.fd.io/images/3/3c/Vpp-tap-container-routing-example.png)

The docker plugin is used to create the VPP tap interface which is attached to the clear container

# How to use this plugin


0. Build this plugin. 

        go build

1. Ensure that your plugin is discoverable https://docs.docker.com/engine/extend/plugin_api/#/plugin-discovery

        sudo cp vpp.json /etc/docker/plugins


2. Start the plugin

        sudo ./vpp &
        
   Note: Enable password less sudo to ensure the plugin will run in the background without prompting.

3. Try VPP with Clear Containers
   Note this is based on the example https://wiki.fd.io/view/VPP/Configure_VPP_TAP_Interfaces_For_Container_Routing

        #Cleanup all containers on the host (dead or alive).
        sudo docker kill `sudo docker ps --no-trunc -aq` ; sudo docker rm `sudo docker ps --no-trunc -aq`

        #Cleanup any old VPP interfaces
        sudo service vpp stop
        sudo service vpp start

        #Create a host side tap for debug
        sudo vppctl tap connect taphost
        sudo vppctl set int ip addr tap-0 192.168.4.1/24
        sudo vppctl set int state tap-0 up

        #Add host TAP IP
        sudo ip addr add 192.168.4.2/24 dev taphost

        #Create the VPP container networks using the custom VPP docker driver
        sudo docker network create -d=vpp --ipam-driver=vpp --subnet=192.168.1.0/24 --gateway=192.168.1.1 --opt "bridge"="none" vpp_2_0
        sudo docker network create -d=vpp --ipam-driver=vpp --subnet=192.168.3.0/24 --gateway=192.168.3.1 --opt "bridge"="none" vpp_3_0

        #Create a docker containers one on each network using the clear container runtime
        #The IP address of each container is specified
        sudo docker run -d --net=vpp_2_0 --ip=192.168.1.2 --mac-address=CA:FE:CA:FE:01:02 --name "hasvpp2" debian bash -c "ip a; ip route; sleep 30000"
        sudo docker run -d --net=vpp_3_0 --ip=192.168.3.2 --mac-address=CA:FE:CA:FE:03:02 --name "hasvpp3" debian bash -c "ip a; ip route; sleep 30000"

        #Check that your containers are running
        sudo docker ps
        ps auxw | grep qemu


        #Add host side routes to the container networks
        sudo ip route add 192.168.1.0/24 via 192.168.4.1
        sudo ip route add 192.168.3.0/24 via 192.168.4.1

        #Test network connectivity from the host to the two clear containers
        ping -c3 192.168.1.2
        ping -c3 192.168.3.2

        #Cleanup
        sudo docker kill `sudo docker ps --no-trunc -aq` ; sudo docker rm `sudo docker ps --no-trunc -aq`
        sudo docker network rm vpp_2_0
        sudo docker network rm vpp_3_0
        sudo service vpp stop
        sudo service vpp start
