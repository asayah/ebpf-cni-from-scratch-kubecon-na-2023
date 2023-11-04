#!/bin/bash

while true; do 
    echo "updating policies" 
    all_ips=`kubectl get pods -A -o custom-columns="POD_IP:.status.podIP" --no-headers=true | xargs echo`  

    #Reset
    for source in $all_ips; do
        for destination in $all_ips; do
        ./iprules $source $destination 1
        done
    done


    all_network_policies=`kubectl get networkpolicies.networking.k8s.io -A -ojson`


    for network_policy in $(kubectl get networkpolicies.networking.k8s.io -A -ojson | jq -c '.items[]'); do
    
    # Get all Destination IPs
    source_label=`echo $network_policy | jq -r '.spec.podSelector.matchLabels.app' `
    policy_destination_ips=`kubectl get pods -A -l app=$source_label -o custom-columns="POD_IP:.status.podIP" --no-headers=true | xargs echo`  

    # Get all Source IPs 
    destination_label=`echo $network_policy | jq -r '.spec.ingress[0].from[0].podSelector.matchLabels.app' `
    policy_source_ips=`kubectl get pods -A -l app=$destination_label -o custom-columns="POD_IP:.status.podIP" --no-headers=true | xargs echo`

    for source in $policy_source_ips; do
        for destination in $policy_destination_ips; do
        echo "blocking $source to $destination"
        ./iprules $source $destination 0
        done
    done
    
    done

sleep 10
done; 