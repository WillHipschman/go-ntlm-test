package main

import (
	"io"
	//"bufio"
	//"net"
	"net/http"
	//"encoding/xml"
	"encoding/base64"
	"bytes"
	"io/ioutil"
	"fmt"
	//"os"
	"github.com/ThomsonReutersEikon/go-ntlm/ntlm"
)

func main() {
	
	var client = &http.Client{}
	var session, _  = ntlm.CreateClientSession(ntlm.Version2, ntlm.ConnectionOrientedMode)
	session.SetUserInfo("user","password","domain")
		
	InitHandShake(client)
	challengeMessage := Negotiate(client, GetNegotiateMessage())
	Challenge(session, client, challengeMessage)
}

func InitHandShake(client *http.Client){
	var request, _ = http.NewRequest("GET", "http://localhost:8080/tfs/DefaultCollection/_git/P1/info/lfs/objects", nil)
	var response, _ = client.Do(request)
	
	printStatus("Init ", response)
	
	io.Copy(ioutil.Discard, response.Body)
	response.Body.Close()
}

func Negotiate(client *http.Client, message string) []byte{
	var request, _ = http.NewRequest("GET", "http://localhost:8080/tfs/DefaultCollection/_git/P1/info/lfs/objects", nil)
	
	request.Header.Add("Authorization", message)
	var response, _ = client.Do(request)
	
	
	printStatus("Stage 1 ", response)	
	
	ret := ParseChallengeMessage(response)
	
	io.Copy(ioutil.Discard, response.Body)
	response.Body.Close()
	
	return ret;
}

func Challenge(session ntlm.ClientSession, client *http.Client, challengeBytes []byte){
	
	challenge, err := ntlm.ParseChallengeMessage(challengeBytes)
	
	if(err != nil){
		panic(err)
	}
	
	session.ProcessChallengeMessage(challenge)
	authenticate, _ := session.GenerateAuthenticateMessage()
	
	authenticateMessage := string(Concat([]byte("NTLM "), []byte(base64.StdEncoding.EncodeToString(authenticate.Bytes()))))
	
	var request, _ = http.NewRequest("GET", "http://localhost:8080/tfs/DefaultCollection/_git/P1/info/lfs/objects", nil)
	
	request.Header.Add("Authorization", authenticateMessage)
	var response, _ = client.Do(request)
	
	printBody(response)
	
	io.Copy(ioutil.Discard, response.Body)
	response.Body.Close()
}

// get the bytes for the Type2 message
func ParseChallengeMessage(response *http.Response) []byte{
	
	if headers, ok := response.Header["Www-Authenticate"]; ok{
		
		//parse out the "NTLM " at the beginning of the resposne
		challenge := headers[0][5:]
		
		val, err := base64.StdEncoding.DecodeString(challenge)
		
		if err != nil{
			panic(err)
		}
		
		return []byte(val)
	}
	
	panic("www-Authenticate header is not present")
}

//Get Type 1 message
func GetNegotiateMessage() string{
		
	var negotiate, _ = session.GenerateNegotiateMessage()
	return negotiate.Bytes
	
	//return "NTLM TlRMTVNTUAABAAAAB7IIogwADAAzAAAACwALACgAAAAKAAAoAAAAD1dJTExISS1NQUlOTk9SVEhBTUVSSUNB"
}

func printStatus(message string, response *http.Response){
	fmt.Println(message)
	fmt.Println(response.Status)	
	fmt.Println("\n")
}

func Concat(ar ...[]byte) []byte {
	return bytes.Join(ar, nil)
}

func printRHeaders(response *http.Request){
	
	fmt.Println("Headers: ")
	
	for key, val := range response.Header {
		fmt.Printf("%s: %s", key, val[0])
		fmt.Println()
	}
	
	fmt.Println("\n")
}

func printRBody(response *http.Request){
	
	printRHeaders(response)
	
	var body, _ = ioutil.ReadAll(response.Body)
	
	fmt.Println(string(body))	
}

func printHeaders(response *http.Response){
	
	fmt.Println("Headers: ")
	
	for key, val := range response.Header {
		fmt.Println("%s: %s", key, val)
	}
	
	fmt.Println("\n")
}

func printBody(response *http.Response){
	
	printHeaders(response)
	
	var body, _ = ioutil.ReadAll(response.Body)
	
	fmt.Println(string(body))	
}

