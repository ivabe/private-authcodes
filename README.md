# zkPaymentCard Verification

Web-based payment cards require sharing the Personal Account Number (PAN), the expiration date, and the Card Verification Value (CVV) with the card issuer. Payment card authorisation is restricted to the card issuer which runs the verification algorithm. It takes as input the shared information (PAN, expiration date), other required codes per specification, such as the service codes, and two private encryption keys. The algorithm outputs the corresponding CVV code. [Reference definition CVV verification.](https://www.ibm.com/docs/en/linux-on-systems?topic=services-cvv-verify-csnbcsv)

Although the payment card data is only necessary to the card issuer for verification purposes, this information is relayed to intermediary parties. Oftentimes, acces control servers perform the authorisation process on behalf of the card issuer. These procedures use transaction risk assessments to determine whether the user is "potentially" the right holder of the credit card. In negative prompting an authentication request in the user end. However, phising sites, and scam attacks are still a reality. 

Leveraging ZKP designated-verifier, this project provides an interface to relay sensitive payment card details to the card issuer only. While intermediary parties can still validate that the shared information is correct. 

## Environment Setup 
```sh
#Docker version 28.0.1
#Docker Compose version v2.33.1

docker-compose build
docker-compose up
```
## App options
```sh
node app/app.js [options]
Options:
-nk,    --newkey <seed>         Generate a new key pair
-nkbj,  --newkeybj              Generate BabyJubJub key pair
-s,     --sign <path1,path2>    Generate a new signature with secret key  [path1] over message  [path2] 
-kex,   --kex <pubkey_path>     Generate an ephemeral key exchange (KEX) from the target public key
-kexf,  --kexfrom <path1,path2> Generate an ephemeral key exchange (KEX) from the given secret key [path1] and kex public key [path2]
-pp,    --packpub <pubkey_path> Compress the public key
-t,     --test                  Verbose testing. Run all commands for verification.
```
## Run test case:
```sh
cd demo
node ../app/app.js --test
```

### Other example use:
```sh
# User
node app/app.js -kex app/target_pubk.json

# Designated_Verifier:
node app/app.js -kexf app/target_sk.json kex.json
```