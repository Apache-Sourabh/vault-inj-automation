#!/bin/bash
VAULT_PROTOCOL="http"
VAULT_URL="localhost:8200"
export VAULT_TOKEN="$1"
VAULT_PATH=("vault-client" "keycloak-client" "grafana-client" "database")

SA_Token=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
SA_CA=$(cat /var/run/secrets/kubernetes.io/serviceaccount/ca.crt)

SA_CERT=$(echo "$SA_CA" | awk 'NF {sub(/\r/, ""); printf "%s\\n",$0;}' )



TOKEN_LOOKUP=$(curl -s --header "X-Vault-Token: $VAULT_TOKEN" --request POST --data '{ "token": "'"$VAULT_TOKEN"'" }' $VAULT_PROTOCOL://$VAULT_URL/v1/auth/token/lookup)
TOKEN_VALIDATE=$(echo $TOKEN_LOOKUP | jq -r .data.display_name)



curl --request POST --header "X-Vault-Token: $VAULT_TOKEN" $VAULT_PROTOCOL://$VAULT_URL/v1/sys/policy/lila-acl-policy --data '{"policy":"path \"lila/'"*"'\" {\n capabilities = [\"list\",\"read\"]\n}"}'

curl --request POST --header "X-Vault-Token:  $VAULT_TOKEN" --data '{"type":"kubernetes","description":"kubernetes auth"}'  $VAULT_PROTOCOL://$VAULT_URL/v1/sys/auth/kubernetes 

curl --request POST --header "X-Vault-Token:  $VAULT_TOKEN" --request POST --data '{ "bound_service_account_names": "vault-auth", "bound_service_account_namespaces": "default","policies": ["lila-acl-policy"]}' $VAULT_PROTOCOL://$VAULT_URL/v1/auth/kubernetes/role/lila-role

curl --header "X-Vault-Token: $VAULT_TOKEN" --request POST --data '{ "kubernetes_host": "http://kubernetes.default.svc.local", "kubernetes_ca_cert": "'"$SA_Token"'", "pem_keys": "'"$SA_CERT"'"
}' $VAULT_PROTOCOL://$VAULT_URL/v1/auth/kubernetes/config