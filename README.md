# cc_vpp

This is simple standalone Docker Plugin implementation to demonstrate Clear Containers with VPP.

For more details about Clear Containers
https://github.com/01org/cc-oci-runtime
https://clearlinux.org/clear-containers

For more information about VPP
https://wiki.fd.io/view/VPP

The docker plugin is used to create the VPP vhost-user interface which is attached to the clear container.
Example below assumes you are using a Clear Container which has VPP enabling.  This can be found at
https://github.com/01org/cc-oci-runtime/tree/networking/vhost-user-poc

# How to use this plugin


0. Build this plugin. 

        go build

1. Ensure that your plugin is discoverable https://docs.docker.com/engine/extend/plugin_api/#/plugin-discovery

        sudo cp vpp.json /etc/docker/plugins/


2. Start the plugin

        sudo ./vpp &
        
   Note: Enable password less sudo to ensure the plugin will run in the background without prompting.

3. Try VPP with Clear Containers

        #Cleanup any old VPP interfaces
        sudo service vpp stop
        sudo service vpp start

        #Create the VPP container network using the custom VPP docker driver
        sudo docker network create -d=vpp --ipam-driver=vpp --subnet=192.168.1.0/24 --gateway=192.168.1.1 vpp_net

        #Create docker containers, testing their connecivity over L2-bridge:
        sudo docker run --net=vpp_net --ip=192.168.1.2 --mac-address=CA:FE:CA:FE:01:02 --name "hasvpp1" -itd debian bash
        sudo docker run --net=vpp_net --ip=192.168.1.3 --mac-address=CA:FE:CA:FE:01:03 --name "hasvpp2" -it debian bash -c "ip a; ip route; ping 192.168.1.2"

        #Cleanup
        sudo docker kill `sudo docker ps --no-trunc -aq` ; sudo docker rm `sudo docker ps --no-trunc -aq`
        sudo docker network rm vpp_net
        sudo service vpp stop
        sudo service vpp start
