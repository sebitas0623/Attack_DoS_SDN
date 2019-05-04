# Attack_DoS_SDN

attack to deny the ONOS controller processing. the attack is deployed from a host in the network, sending a lot of ICMP packets with spoofed source MAC, garanting that the packets must be sent to the controller.

run it this way: 
  
    python3 attack.py <IP_Target>
    
 where IP_Target is the ip address to send the ICMP packets.
