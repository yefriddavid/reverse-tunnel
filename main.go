/*
Go-Language implementation of an SSH Reverse Tunnel, the equivalent of below SSH command:
   ssh -R 8080:127.0.0.1:8080 operatore@146.148.22.123
which opens a tunnel between the two endpoints and permit to exchange information on this direction:
   server:8080 -----> client:8080
   once authenticated a process on the SSH server can interact with the service answering to port 8080 of the client
   without any NAT rule via firewall
Copyright 2017, Davide Dal Farra
MIT License, http://www.opensource.org/licenses/mit-license.php
*/

package main

import (
	"flag"
	"fmt"
	goversion "github.com/caarlos0/go-version"
	"golang.org/x/crypto/ssh"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"strconv"
	"time"
)

var (
	action                = flag.String("action", "reverse-tunnel", "reverse-tunnel, fordard-ports")
	argServerSshKeyFile   = flag.String("serverSshKeyFile", "", "ssh key file")
	argServerSshUsername  = flag.String("serverSshUsername", "", "ssh username")
	argServerSshPort      = flag.String("serverSshPort", "", "ssh port")
	argServerEndpointHost = flag.String("serverEndpointHost", "", "endpoint host")
	argRemoteEndpointHost = flag.String("remoteEndpointHost", "", "endpoint host")
	argRemoteEndpointPort = flag.String("remoteEndpointPort", "", "endpoint port")
	argLocalEndpointPort  = flag.String("localEndpointPort", "", "local port")
	argLocalEndpointHost  = flag.String("localEndpointHost", "", "local host")
)

var (
	version   = ""
	commit    = ""
	treeState = ""
	date      = ""
	builtBy   = ""
)
var serverSshKeyFile string = ""
var serverSshUsername string = ""
var serverSshPort string = ""
var serverEndpointHost string = ""
var remoteEndpointHost string = ""
var remoteEndpointPort string = ""
var localEndpointPort string = ""
var localEndpointHost string = ""

//var serverSshKeyFile string = "/mnt/Zeus/Workspace/traze/sec/tzweb-api.pem"
//var serverSshUsername string = "ubuntu"
//var serverSshPort string = "51122"
//var serverEndpointHost string = "3.92.69.78"
//var remoteEndpointHost string = "0.0.0.0"
//var remoteEndpointPort string = "8082"
//var localEndpointPort string = "8082"
//var localEndpointHost string = "localhost"

const website = "https://goreleaser.com"

var asciiArt string

type Endpoint struct {
	Host string
	Port int
}

func (endpoint *Endpoint) String() string {
	return fmt.Sprintf("%s:%d", endpoint.Host, endpoint.Port)
}

// From https://sosedoff.com/2015/05/25/ssh-port-forwarding-with-go.html
// Handle local client connections and tunnel data to the remote server
// Will use io.Copy - http://golang.org/pkg/io/#Copy

func init() {
	flag.Parse()

	readCommonParameters()
	switch ac := *action; ac {
	case "reverse-tunnel":
		readParamsReverseTunnel()
	case "port-forwarding":
		//readParamsReverseTunnel();
		readParamsFordardPorts()
	default:
		// freebsd, openbsd,
		// plan9, windows...
		fmt.Printf("Not Action Valid! %s.\n", ac)
	}
}

func main() {

	switch ac := *action; ac {
	case "reverse-tunnel":
		startReverseTunnel()
	case "port-forwarding":
		startPortForwarind()
	default:
		fmt.Printf("Not Action Valid! %s.\n", ac)
	}
}

func readParamsFordardPorts() {

}
func readParamsReverseTunnel() {

}
func readCommonParameters() {

	if *argServerSshKeyFile == "" {
		if os.Getenv("SERVER_SSH_KEY_FILE") != "" {
			serverSshKeyFile = os.Getenv("SERVER_SSH_KEY_FILE")
		}
	} else {
		serverSshKeyFile = *argServerSshKeyFile
	}

	if *argServerSshUsername == "" {
		if os.Getenv("SERVER_SSH_USERNAME") != "" {
			serverSshUsername = os.Getenv("SERVER_SSH_USERNAME")
		}
	} else {
		serverSshUsername = *argServerSshUsername

	}

	if *argServerSshPort == "" {
		if os.Getenv("SERVER_SSH_PORT") != "" {

			serverSshPort = os.Getenv("SERVER_SSH_PORT")

		}

	} else {
		serverSshPort = *argServerSshPort

	}

	if *argServerEndpointHost == "" {
		if os.Getenv("SERVER_ENDPOINT_HOST") != "" {

			serverEndpointHost = os.Getenv("SERVER_ENDPOINT_HOST")
		}
	} else {
		serverEndpointHost = *argServerEndpointHost

	}

	if *argRemoteEndpointHost == "" {
		if os.Getenv("REMOTE_ENDPOINT_HOST") != "" {
			remoteEndpointHost = os.Getenv("REMOTE_ENDPOINT_HOST")

		}
	} else {
		remoteEndpointHost = *argRemoteEndpointHost

	}

	if *argRemoteEndpointPort == "" {
		if os.Getenv("REMOTE_ENDPOINT_PORT") != "" {

			remoteEndpointPort = os.Getenv("REMOTE_ENDPOINT_PORT")
		}

	} else {
		remoteEndpointPort = *argRemoteEndpointPort

	}

	if *argLocalEndpointPort == "" {
		if os.Getenv("LOCAL_ENDPOINT_PORT") != "" {
			localEndpointPort = os.Getenv("LOCAL_ENDPOINT_PORT")
		}
	} else {
		localEndpointPort = *argLocalEndpointPort

	}

	if *argLocalEndpointHost == "" {
		if os.Getenv("LOCAL_ENDPOINT_HOST") != "" {
			localEndpointHost = os.Getenv("LOCAL_ENDPOINT_HOST")
		}
	} else {
		localEndpointHost = *argLocalEndpointHost

	}

	argServerSshPort, _ := strconv.Atoi(serverSshPort)
	argRemoteEndpointPort, _ := strconv.Atoi(remoteEndpointPort)
	argLocalEndpointPort, _ := strconv.Atoi(localEndpointPort)

	serverEndpoint = Endpoint{
		Host: serverEndpointHost,
		Port: argServerSshPort,
	}
	remoteEndpoint = Endpoint{
		Host: remoteEndpointHost,
		Port: argRemoteEndpointPort,
	}
	localEndpoint = Endpoint{
		Host: localEndpointHost,
		Port: argLocalEndpointPort,
	}

	fmt.Println("serverSshKeyFile", serverSshKeyFile)
	fmt.Println("serverSshUsername", "**********")
	fmt.Println("serverSshPort", serverSshPort)
	fmt.Println("serverEndpointHost", serverEndpointHost)
	fmt.Println("remoteEndpointHost", remoteEndpointHost)
	fmt.Println("remoteEndpointPort", remoteEndpointPort)
	fmt.Println("localEndpointPort", localEndpointPort)
	fmt.Println("localEndpointHost", localEndpointHost)
}

func startPortForwarind() {
	// ln, err := net.Listen("tcp", ":8000")
	fmt.Println(localEndpoint.String())
	if true {
		//return
	}
	ln, err := net.Listen("tcp", localEndpoint.String())
	if err != nil {
		panic(err)
	}

	for {
		conn, err := ln.Accept()
		if err != nil {
			panic(err)
		}

		go handleRequestPortForwarding(conn)
	}

}
func startReverseTunnel() {

	// refer to https://godoc.org/golang.org/x/crypto/ssh for other authentication types
	sshConfig := &ssh.ClientConfig{
		// SSH connection username
		// User: "ubuntu",
		User: serverSshUsername,
		Auth: []ssh.AuthMethod{
			// put here your private key path
			// publicKeyFile("/mnt/Zeus/Workspace/traze/sec/tzweb-api.pem"),
			publicKeyFile(serverSshKeyFile),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	// Connect to SSH remote server using serverEndpoint

	serverConn, err := ssh.Dial("tcp", serverEndpoint.String(), sshConfig)
	if err != nil {
		log.Fatalln(fmt.Printf("Dial INTO remote server error: %s", err))
	}

	// Listen on remote server port
	listener, err := serverConn.Listen("tcp", remoteEndpoint.String())
	if err != nil {
		log.Fatalln(fmt.Printf("Listen open port ON remote server error: %s", err))
	}
	defer listener.Close()

	// handle incoming connections on reverse forwarded tunnel
	for {
		// Open a (local) connection to localEndpoint whose content will be forwarded so serverEndpoint
		local, err := net.Dial("tcp", localEndpoint.String())
		if err != nil {
			// log.Fatalln(fmt.Printf("Dial INTO local service error: %s", err))
			log.Println(fmt.Printf("Dial INTO local service error: %s", err))
			time.Sleep(5 * time.Second)
			//continue
		} else {

			client, err := listener.Accept()
			if err != nil {
				log.Fatalln(err)
			}

			handleClientReverseTunnel(client, local)
		}
	}
}

func handleClientReverseTunnel(client net.Conn, remote net.Conn) {
	defer client.Close()
	chDone := make(chan bool)

	// Start remote -> local data transfer
	go func() {
		_, err := io.Copy(client, remote)
		if err != nil {
			log.Println(fmt.Sprintf("error while copy remote->local: %s", err))
		}
		chDone <- true
	}()

	// Start local -> remote data transfer
	go func() {
		_, err := io.Copy(remote, client)
		if err != nil {
			log.Println(fmt.Sprintf("error while copy local->remote: %s", err))
		}
		chDone <- true
	}()

	<-chDone
}

func publicKeyFile(file string) ssh.AuthMethod {
	buffer, err := ioutil.ReadFile(file)
	if err != nil {
		log.Fatalln(fmt.Sprintf("Cannot read SSH public key file %s", file))
		return nil
	}

	key, err := ssh.ParsePrivateKey(buffer)
	if err != nil {
		log.Fatalln(fmt.Sprintf("Cannot parse SSH public key file %s", file))
		return nil
	}
	return ssh.PublicKeys(key)
}

// local service to be forwarded
var localEndpoint Endpoint

// remote SSH server
var serverEndpoint Endpoint

/*var serverEndpoint = Endpoint{
	Host: "3.92.69.78",
	Port: 51122,
}*/

// remote forwarding port (on remote SSH server network)
var remoteEndpoint Endpoint

func main2() {

	fmt.Println(serverEndpoint.String())

}
func buildVersion(version, commit, date, builtBy, treeState string) goversion.Info {
	return goversion.GetVersionInfo(
		goversion.WithAppDetails("goreleaser", "Deliver Go Binaries as fast and easily as possible", website),
		goversion.WithASCIIName(asciiArt),
		func(i *goversion.Info) {
			if commit != "" {
				i.GitCommit = commit
			}
			if treeState != "" {
				i.GitTreeState = treeState
			}
			if date != "" {
				i.BuildDate = date
			}
			if version != "" {
				i.GitVersion = version
			}
			if builtBy != "" {
				i.BuiltBy = builtBy
			}
		},
	)
}

/*Port forwarding*/
func handleRequestPortForwarding(conn net.Conn) {
	fmt.Println("new client")

	// proxy, err := net.Dial("tcp", "127.0.0.1:8082")
	fmt.Println(remoteEndpoint.String())
	proxy, err := net.Dial("tcp", remoteEndpoint.String())
	if err != nil {
		panic(err)
	}

	fmt.Println("proxy connected")
	go copyIO(conn, proxy)
	go copyIO(proxy, conn)
}

func copyIO(src, dest net.Conn) {
	defer src.Close()
	defer dest.Close()
	io.Copy(src, dest)
}
