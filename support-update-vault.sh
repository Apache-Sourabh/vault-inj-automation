#/bin/bash
#Script to post data into Vault
#Script supports fetching keycloak client ID & Secret from single Realm

#---------------------#
#Keycloak input details
#---------------------#
KEYCLOAK_PROTOCOL="http"
KEYCLOAK_URL="keycloak.vault" 
#export KEYCLOAK_ADMIN_USERNAME="$1"
#export KEYCLOAK_ADMIN_PASSWORD="$2"
KC_ADMIN_USERNAME=$(echo $KEYCLOAK_ADMIN_USERNAME)                                                                                                                              
KC_ADMIN_PASSWORD=$(echo $KEYCLOAK_ADMIN_PASSWORD)
KEYCLOAK_REALMS="Livinglab"
KEYCLOAK_CLIENT_NAMES=("argo" "grafana-oauth" "hashicorpvault" "kubeapps")
#---------------------#
#Vault input details
#---------------------#
VAULT_PROTOCOL="http"
VAULT_URL="vault.vault:8200"
VAULT_TOKEN=$(echo $VAULT_ROOT_TOKEN)
#export VAULT_TOKEN="$3"
APP_NAME="argo"
#---------------------#

#    if [ $# -lt 3 ]; then
#        echo "####################################################" 
#        echo "One or more argument is missing."
#        echo 'script execution: "sh update-vault.sh <keycloak-admin-username> <keycloak-admin-password> <vault-root-token>"'
#        echo "####################################################"
#        exit
#    fi

    unseal_status=$(curl -s $VAULT_PROTOCOL://$VAULT_URL/v1/sys/seal-status | jq -r .sealed)

    if [ "$unseal_status" == "false" ]; then
        
        TOKEN_LOOKUP=$(curl -s --header "X-Vault-Token: $VAULT_TOKEN" --request POST --data '{ "token": "'"$VAULT_TOKEN"'" }' $VAULT_PROTOCOL://$VAULT_URL/v1/auth/token/lookup)
        TOKEN_VALIDATE=$(echo $TOKEN_LOOKUP | jq -r .data.display_name)

        if [ $TOKEN_VALIDATE == "root" ]; then
            echo ""
            echo "####################################################"
            echo "*** Vault login success ***"
            echo "####################################################"
            echo ""
        elif [ "$TOKEN_VALIDATE" == "null" ]; then
            echo ""
            echo "####################################################"
            echo "Vault Login failed, please check vault details viz. Vault-URL and Root-Token"
            echo "####################################################" 
            echo ""
            exit
        fi
    elif [ "$unseal_status" == "true" ]; then
        echo ""
        echo "####################################################"
        echo "*** Vault is sealed ***"
        echo "####################################################"
        echo ""
        exit
    fi

    



#Function to FETCH Keycloak Client data
fetch_client_data () {

    echo "####################################################"
    echo "*** Fetching Bearer token ***"
    echo "####################################################"
    echo ""

    #Token_data=$(curl -s --fail $KEYCLOAK_PROTOCOL://$KEYCLOAK_URL/realms/master/protocol/openid-connect/token -H 'Content-Type: application/x-www-form-urlencoded' -d "grant_type=password&username=$KC_ADMIN_USERNAME&password=$KC_ADMIN_PASSWORD&client_id=admin-cli")
    

    Token_data=$(curl -s --fail $KEYCLOAK_PROTOCOL://$KEYCLOAK_URL/realms/master/protocol/openid-connect/token -H 'Content-Type: application/x-www-form-urlencoded' -d 'client_id=admin-cli' -d "username="$KC_ADMIN_USERNAME"" -d "password="$KC_ADMIN_PASSWORD"" -d 'grant_type=password')

    if [ $? -eq 0 ]; then
        echo "####################################################"
        echo "*** Bearer token successfully fetched ***"
        echo "####################################################"
        echo ""
    else 
        echo "####################################################"
        echo "*** Error while fetching bearer token ***"
        echo "Please check the keycloak admin credentials and other details"
        echo "####################################################"
        echo ""
        exit
    fi

    KEYCLOAK_ACCESS_TOKEN=$(echo $Token_data | jq -r .access_token)

    clients=$(curl -s --fail $KEYCLOAK_PROTOCOL://$KEYCLOAK_URL/admin/realms/$KEYCLOAK_REALMS/clients -H 'Content-Type: application/json' -H  "Authorization: Bearer $KEYCLOAK_ACCESS_TOKEN")
   
    if [ $? -ne 0 ]; then
        echo "####################################################"
        echo "*** Error while fetching client ***"
        echo "Provided realm is $KEYCLOAK_REALMS, please verify?"
        echo "####################################################"
        echo ""
        exit
    fi


    client_check=( $( printf '%s\n' "${KEYCLOAK_CLIENT_NAMES[@]}" | grep -i "$APP_NAME" ) )
    if [ ! -z "$client_check" ]; then
        client_id=$(echo $clients | jq -r --arg kc ${client_check} '.[] | select(.clientId==$kc) | .id' )
        
        if [ $? -ne 0 ]; then
        echo "####################################################"
        echo "*** Error while fetching client ID ***"
        echo "Provided Client name is $client_check, please verify?"
        echo "####################################################"
        echo ""
        exit
        fi

        echo "####################################################"
        echo "*** $client_check ID successfully fetched ***"
        echo "####################################################"
        echo ""

        secret_data=$(curl -s $KEYCLOAK_PROTOCOL://$KEYCLOAK_URL/admin/realms/$KEYCLOAK_REALMS/clients/$client_id/client-secret -H 'Content-Type: application/json' -H  "Authorization: Bearer $KEYCLOAK_ACCESS_TOKEN")

        client_secret=$(echo $secret_data | jq -r .value)

        echo "####################################################"
        echo "*** $client_check secret successfully fetched ***"
        echo "####################################################"
        echo ""
    
    fi

    prep_vault_auth 

}


prep_vault_auth () {

    #SA_Token=$(cat ./token)
    #SA_CA=$( cat ./ca.crt)

    SA_Token=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
    SA_CA=$(cat /var/run/secrets/kubernetes.io/serviceaccount/ca.crt)

    SA_CERT=$(echo "$SA_CA" | awk 'NF {sub(/\r/, ""); printf "%s\\n",$0;}' )

    #############create lila-acl policy###############
    check_policy=$(curl -s --request GET --header "X-Vault-Token: $VAULT_TOKEN" $VAULT_PROTOCOL://$VAULT_URL/v1/sys/policy/lila-acl-policy | jq -r .name )
    if [ "$check_policy"  == "null" ]; then
        curl -s --request POST --header "X-Vault-Token: $VAULT_TOKEN" $VAULT_PROTOCOL://$VAULT_URL/v1/sys/policy/lila-acl-policy --data '{"policy":"path \"livinglab/'"*"'\" {\n capabilities = [\"list\",\"read\"]\n}"}'
        echo "####################################################"
        echo "*** created lila-vault-policy ***"
        echo "####################################################"
        echo ""
    else
        echo "####################################################"
        echo "*** lila-vault-policy already exists ***"
        echo "####################################################"
        echo ""
    fi
    ####################################################

    ###############enable kubernetes auth###############
    k8s_auth_enabled=$(curl -s --request GET --header "X-Vault-Token:  $VAULT_TOKEN" $VAULT_PROTOCOL://$VAULT_URL/v1/sys/auth/kubernetes  | jq -r .type)
    if [ "$k8s_auth_enabled"  == "null" ]; then
        curl -s --request POST --header "X-Vault-Token:  $VAULT_TOKEN" --data '{"type":"kubernetes","description":"kubernetes auth"}'  $VAULT_PROTOCOL://$VAULT_URL/v1/sys/auth/kubernetes
        echo "####################################################"
        echo "*** enabled kubernetes auth ***"
        echo "####################################################"
        echo ""
    else
        echo "####################################################"
        echo "*** kubernetes auth already exists ***"
        echo "####################################################"
        echo ""
    fi
    ####################################################
   
    ###############create lila-vault-role###############
    lila_role_exists=$(curl -s --request GET --header "X-Vault-Token:  $VAULT_TOKEN" $VAULT_PROTOCOL://$VAULT_URL/v1/auth/kubernetes/role/lila-vault-role | jq -r .request_id )
    if [ "$lila_role_exists"  == "null" ]; then
        curl -s --request POST --header "X-Vault-Token:  $VAULT_TOKEN" --request POST --data '{ "bound_service_account_names" : ["lila-grafana-sa", "lila-argocd-sa","lila-daps-sa","lila-edc-sa","lila-mvd-sa","lila-datadashboard-sa","mvd-connector-deployment-edc-mvd-vault","keycloak-sa","argocd-sa","grafana-sa","tibco-sa"], "bound_service_account_namespaces" : ["grafana","livinglab-argocd","daps","edc","mvd","datadashboard","livinglab-grafana","livinglab-keycloak","tibco"] , "policies" : ["lila-acl-policy"]}' $VAULT_PROTOCOL://$VAULT_URL/v1/auth/kubernetes/role/lila-vault-role
        echo "####################################################"
        echo "*** created lila-vault-role ***"
        echo "####################################################"
        echo ""
    else
        echo "####################################################"
        echo "*** lila-vault-role already exists ***"
        echo "####################################################"
        echo ""
    fi
    ####################################################

    ###############create k8s auth config###############
    config_exists=$(curl -s --header "X-Vault-Token: $VAULT_TOKEN" --request GET  $VAULT_PROTOCOL://$VAULT_URL/v1/auth/kubernetes/config | jq -r .request_id )
    if [ "$config_exists"  == "null" ]; then
        curl -s --header "X-Vault-Token: $VAULT_TOKEN" --request POST --data '{ "kubernetes_host": "http://kubernetes.default.svc.local", "kubernetes_ca_cert": "'"$SA_Token"'", "pem_keys": "'"$SA_CERT"'" }' $VAULT_PROTOCOL://$VAULT_URL/v1/auth/kubernetes/config
        echo "####################################################"
        echo "*** created kubernetes auth config ***"
        echo "####################################################"
        echo ""
    else
        echo "####################################################"
        echo "*** kubernetes auth already exists ***"
        echo "####################################################"
        echo ""
    fi
    ####################################################

    post_vault_data
}

#Function to POST data into vault
post_vault_data () {


    ###############create kv2 secret path###############
    secret_exists=$(curl -s --request GET --header "X-Vault-Token:  $VAULT_TOKEN" $VAULT_PROTOCOL://$VAULT_URL/v1/sys/mounts/livinglab  | jq -r .config)
    if [ "$secret_exists" == "null" ]; then
        curl -s --header "X-Vault-Token: $VAULT_TOKEN" --request POST --data '{"type":"kv","config" : {"default_lease_ttl":0,"force_no_cache":false,"max_lease_ttl":0}, "options": {"version": "2"}}' $VAULT_PROTOCOL://$VAULT_URL/v1/sys/mounts/livinglab
        echo "####################################################"
        echo "*** created KV2 secret ***"
        echo "####################################################"
        echo ""
    else
        echo "####################################################"
        echo "*** KV2 secret already exists ***"
        echo "####################################################"
        echo ""
    fi
    ####################################################

   #####POST DATA INTO SUB-PATH######

    
   if [[ "$APP_NAME" == *"argo"* ]]; then
        
        path_list=$(curl -s --request GET --header "X-Vault-Token: $VAULT_TOKEN" $VAULT_PROTOCOL://$VAULT_URL/v1/livinglab/metadata/?list=true | jq -r '.data.keys' | jq -r .[] | grep -i "$APP_NAME")

        if [[ -z $path_list  ]]; then
            clearPassword=$(tr -dc A-Za-z0-9 </dev/urandom | head -c 13 ; echo '')
            bcrpytPassword=$(htpasswd -nbBC 10 "" "$clearPassword" | tr -d ':\n' | sed 's/$2y/$2a/')
            curl -s -o /dev/null --request POST --header "X-Vault-Token:  $VAULT_TOKEN" --data '{"data":{"clearPassword":"'"$clearPassword"'","oidc.auth0.clientSecret":"'"$client_secret"'","admin.password":"'"$bcrpytPassword"'"}}' $VAULT_PROTOCOL://$VAULT_URL/v1/livinglab/data/argocd/argocd-oidc-secret
            curl -s -o /dev/null --request POST --header "X-Vault-Token:  $VAULT_TOKEN" --data '{"data":{"oidc-kc-root-ca.crt":""}}' $VAULT_PROTOCOL://$VAULT_URL/v1/livinglab/data/argocd/argocd-vault-secret
            echo "####################################################"
            echo "*** Added ARGO Data into vault ***"
            echo "####################################################"
            echo ""
        fi
   elif [[ "$APP_NAME" == *"grafana"* ]]; then

        path_list=$(curl -s --request GET --header "X-Vault-Token: $VAULT_TOKEN" $VAULT_PROTOCOL://$VAULT_URL/v1/livinglab/metadata/?list=true | jq -r '.data.keys' | jq -r .[] | grep -i "$APP_NAME")

        if [[ -z $path_list  ]]; then
            curl -s -o /dev/null --request POST --header "X-Vault-Token:  $VAULT_TOKEN" --data '{"data":{"client_id":"'"$client_check"'","client_secret":"'"$client_secret"'"}}' $VAULT_PROTOCOL://$VAULT_URL/v1/livinglab/data/grafana
            echo "####################################################"
            echo "*** Added GRAFANA into vault ***"
            echo "####################################################"
            echo ""
        fi

    elif [[ "$APP_NAME" == *"kubeapps"* ]]; then
        path_list=$(curl -s --request GET --header "X-Vault-Token: $VAULT_TOKEN" $VAULT_PROTOCOL://$VAULT_URL/v1/livinglab/metadata/?list=true | jq -r '.data.keys' | jq -r .[] | grep -i "$APP_NAME")

        if [[ -z $path_list  ]]; then
            curl -s -o /dev/null --request POST --header "X-Vault-Token:  $VAULT_TOKEN" --data '{"data":{"client_id":"'"$client_check"'","client_secret":"'"$client_secret"'"}}' $VAULT_PROTOCOL://$VAULT_URL/v1/livinglab/data/kubeapps/keycloak-secret  
            echo "####################################################"
            echo "*** Added KUBEAPPS Data into vault ***"
            echo "####################################################"
            echo ""
        fi
    fi

}

fetch_client_data
