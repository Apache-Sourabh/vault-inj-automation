#/bin/bash
#Script to post data into Vault
#Script supports fetching keycloak client ID & Secret from single Realm
#Developed by sourabh.patil@t-systems.com, in case of any support, please reach out to same via email.
#Thank you

#---------------------#
#Keycloak input details
#---------------------#
KEYCLOAK_PROTOCOL="http"
KEYCLOAK_URL="localhost:8080" 
export KEYCLOAK_ADMIN_USERNAME="$1"
export KEYCLOAK_ADMIN_PASSWORD="$2"
KEYCLOAK_REALMS="lila"
KEYCLOAK_CLIENT_NAMES=("vault-client" "keycloak-client" "grafana-client")
#---------------------#
#Vault input details
#---------------------#
VAULT_PROTOCOL="http"
VAULT_URL="localhost:8200"
export VAULT_TOKEN="$3"
VAULT_PATH=("vault-client" "keycloak-client" "grafana-client" "database")
Vault_Data=("grafana" "keycloak" "vault" "database")
#---------------------#


if [ $# -lt 2 ]; then
   echo "One or more argument is missing."
   echo 'script execution: "sh update-vault.sh <keycloak-admin-username> <keycloak-admin-password> <vault-root-token>"'
   exit
fi

TOKEN_LOOKUP=$(curl -s --header "X-Vault-Token: $VAULT_TOKEN" --request POST --data '{ "token": "'"$VAULT_TOKEN"'" }' $VAULT_PROTOCOL://$VAULT_URL/v1/auth/token/lookup)
TOKEN_VALIDATE=$(echo $TOKEN_LOOKUP | jq -r .data.display_name)


    if [ $TOKEN_VALIDATE == "root" ]; then
        echo ""
        echo "####################################################"
        echo "Vault login success"
        echo "####################################################"
        echo ""
        continue
    elif [ "$TOKEN_VALIDATE" == "null" ]; then
        echo ""
        echo "####################################################"
        echo "Vault Login failed, please check vault details viz. Vault-URL and Root-Token"
        echo "####################################################" 
        echo ""
        exit
    fi



prep_vault_auth () {

    SA_Token=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
    SA_CA=$(cat /var/run/secrets/kubernetes.io/serviceaccount/ca.crt)

    SA_CERT=$(echo "$SA_CA" | awk 'NF {sub(/\r/, ""); printf "%s\\n",$0;}' )


    #create lila-acl policy
    curl --request POST --header "X-Vault-Token: $VAULT_TOKEN" $VAULT_PROTOCOL://$VAULT_URL/v1/sys/policy/lila-acl-policy --data '{"policy":"path \"lila/'"*"'\" {\n capabilities = [\"list\",\"read\"]\n}"}'

    #enable kubernetes auth (add condition)

    k8s_auth_enabled=$(curl -s --request GET --header "X-Vault-Token:  hvs.DgPKvJIxf4vsNvrzCCsszyJW" --data '{"type":"kubernetes","description":"kubernetes auth"}'  http://vault.vault.svc.cluster.local:8200/v1/sys/auth/kubernetes  | jq -r .type)

    if [ "$k8s_auth_enabled"  == "null" ]; then
        curl --request POST --header "X-Vault-Token:  $VAULT_TOKEN" --data '{"type":"kubernetes","description":"kubernetes auth"}'  $VAULT_PROTOCOL://$VAULT_URL/v1/sys/auth/kubernetes 
    fi
    
    path=( $( printf '%s\n' "${VAULT_PATH[@]}" | grep -i "$1" ) )

    #if [ ! -z "$path" ] && [ "$path" != "database" ]; then
    #    Post_role=$(curl --request POST --header "X-Vault-Token:  $VAULT_TOKEN" --request POST --data '{ "bound_service_account_names": "vault-auth", "bound_service_account_namespaces": "default","policies": ["lila-acl-policy"]}' $VAULT_PROTOCOL://$VAULT_URL/v1/auth/kubernetes/role/lila-role)
    #elif [ ! -z "$path" ] && [ "$path" == "database" ]; then
    #    Post_role=$(curl --request POST --header "X-Vault-Token:  $VAULT_TOKEN" --request POST --data '{ "bound_service_account_names": "vault-auth", "bound_service_account_namespaces": "default","policies": ["lila-acl-policy"]}' $VAULT_PROTOCOL://$VAULT_URL/v1/auth/kubernetes/role/lila-role)
    #fi

    curl --request POST --header "X-Vault-Token:  $VAULT_TOKEN" --request POST --data '{ "bound_service_account_names": "vault-auth", "bound_service_account_namespaces": "default","policies": ["lila-acl-policy"]}' $VAULT_PROTOCOL://$VAULT_URL/v1/auth/kubernetes/role/lila-role

    curl --header "X-Vault-Token: $VAULT_TOKEN" --request POST --data '{ "kubernetes_host": "http://kubernetes.default.svc.local", "kubernetes_ca_cert": "'"$SA_Token"'", "pem_keys": "'"$SA_CERT"'" }' $VAULT_PROTOCOL://$VAULT_URL/v1/auth/kubernetes/config
}

#Function to POST data into vault
post_vault_data () {

    path=( $( printf '%s\n' "${VAULT_PATH[@]}" | grep -i "$1" ) )

    if [ ! -z "$path" ] && [ "$path" != "database" ]; then
        Post_Data=$(curl -s -H "X-Vault-Token: $VAULT_TOKEN" -H "Content-Type: application/json" -X POST -d '{"data":{"client-id":"'"$client_check"'","client-secret":"'"$client_secret"'"}}' "$VAULT_PROTOCOL://$VAULT_URL/v1/secret/data/$path")
    elif [ ! -z "$path" ] && [ "$path" == "database" ]; then
        Post_Data=$(curl -s -H "X-Vault-Token: $VAULT_TOKEN" -H "Content-Type: application/json" -X POST -d '{"data":{"password":"'"$client_secret"'"}}' "$VAULT_PROTOCOL://$VAULT_URL/v1/secret/data/$path")
    fi

}

#Function to FETCH Keycloak Client data
fetch_client_data () {

    echo "####################################################"
    echo "***Fetching Bearer token***"
    echo "####################################################"
    echo ""

    Token_data=$(curl -s --fail $KEYCLOAK_PROTOCOL://$KEYCLOAK_URL/realms/master/protocol/openid-connect/token -H 'Content-Type: application/x-www-form-urlencoded' -d "grant_type=password&username=$KEYCLOAK_ADMIN_USERNAME&password=$KEYCLOAK_ADMIN_PASSWORD&client_id=admin-cli")
    
    if [ $? -eq 0 ]; then
        echo "####################################################"
        echo "***Bearer token successfully fetched***"
        echo "####################################################"
        echo ""
    else 
        echo "####################################################"
        echo "***Error while fetching bearer token***"
        echo "Please check the keycloak admin credentials and other details"
        echo "####################################################"
        echo ""
        exit
    fi

    KEYCLOAK_ACCESS_TOKEN=$(echo $Token_data | jq -r .access_token)

    clients=$(curl -s --fail $KEYCLOAK_PROTOCOL://$KEYCLOAK_URL/admin/realms/$KEYCLOAK_REALMS/clients -H 'Content-Type: application/json' -H  "Authorization: Bearer $KEYCLOAK_ACCESS_TOKEN")
   
    if [ $? -ne 0 ]; then
        echo "####################################################"
        echo "***Error while fetching client***"
        echo "Provided realm is $KEYCLOAK_REALMS, please verify?"
        echo "####################################################"
        echo ""
        exit
    fi


    client_check=( $( printf '%s\n' "${KEYCLOAK_CLIENT_NAMES[@]}" | grep -i "$1" ) )
    if [ ! -z "$client_check" ]; then
        client_id=$(echo $clients | jq -r --arg kc ${client_check} '.[] | select(.clientId==$kc) | .id' )
        
        if [ $? -ne 0 ]; then
        echo "####################################################"
        echo "***Error while fetching client ID***"
        echo "Provided Client name is $client_check, please verify?"
        echo "####################################################"
        echo ""
        exit
        fi

        echo "####################################################"
        echo "*** $client_check ID successfully fetched***"
        echo "####################################################"
        echo ""

        secret_data=$(curl -s $KEYCLOAK_PROTOCOL://$KEYCLOAK_URL/admin/realms/$KEYCLOAK_REALMS/clients/$client_id/client-secret -H 'Content-Type: application/json' -H  "Authorization: Bearer $KEYCLOAK_ACCESS_TOKEN")

        client_secret=$(echo $secret_data | jq -r .value)

        echo "####################################################"
        echo "*** $client_check secret successfully fetched***"
        echo "####################################################"
        echo ""
        echo "-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/-/"
        echo ""
    
    fi

    prep_vault_auth "$1"

}

for i in ${Vault_Data[@]}; do
    fetch_client_data "$i"
done