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
)

var (
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
	if serverSshKeyFile != "" {
        if serverSshKeyFile = os.Getenv("SERVER_SSH_KEY_FILE"); serverSshKeyFile == "" {
            serverSshKeyFile = *argServerSshKeyFile
        }
    }

	if serverSshUsername != "" {
        if serverSshUsername = os.Getenv("SERVER_SSH_USERNAME"); serverSshUsername == "" {
            serverSshUsername = *argServerSshUsername
        }
	}

	if serverSshPort != "" {
        if serverSshPort := os.Getenv("SERVER_SSH_PORT"); serverSshPort == "" {
            serverSshPort = *argServerSshPort
        } else {
            //serverSshPort, _ = strconv.Atoi(envServerSshPort)
        }
    }

	// if remoteEndpointHost = os.Getenv("SERVER_ENDPOINT_HOST");remoteEndpointHost== "" {
	if serverEndpointHost != "" {
        if serverEndpointHost = os.Getenv("SERVER_ENDPOINT_HOST"); serverEndpointHost == "" {
            serverEndpointHost = *argRemoteEndpointHost
        }
	}

	if remoteEndpointHost != "" {
        if remoteEndpointHost = os.Getenv("REMOTE_ENDPOINT_HOST"); remoteEndpointHost == "" {
            remoteEndpointHost = *argRemoteEndpointHost
        }
    }

	if remoteEndpointPort != "" {
        if remoteEndpointPort := os.Getenv("REMOTE_ENDPOINT_PORT"); remoteEndpointPort == "" {
            remoteEndpointPort = *argRemoteEndpointPort
        } else {
            //remoteEndpointPort, _ = strconv.Atoi(envRemoteEndpointPort)
        }
    }

	if localEndpointPort != "" {
        if localEndpointPort := os.Getenv("LOCAL_ENDPOINT_PORT"); localEndpointPort == "" {
            localEndpointPort = *argLocalEndpointPort
        } else {
            // localEndpointPort, _ = strconv.Atoi(envLocalEndpointPort)
        }
    }

	if localEndpointHost != "" {
        if localEndpointHost = os.Getenv("LOCAL_ENDPOINT_HOST"); localEndpointHost == "" {
            localEndpointHost = *argLocalEndpointHost
        }
	}

    argServerSshPort, _ := strconv.Atoi(serverSshPort)
	argRemoteEndpointPort, _ := strconv.Atoi(remoteEndpointPort)
	argLocalEndpointPort, _	:= strconv.Atoi(localEndpointPort)

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

fmt.Println(serverSshKeyFile)
fmt.Println(serverSshUsername)
fmt.Println(serverSshPort)
fmt.Println(serverEndpointHost)
fmt.Println(remoteEndpointHost)
fmt.Println(remoteEndpointPort)
fmt.Println(localEndpointPort)
fmt.Println(localEndpointHost)
}

func handleClient(client net.Conn, remote net.Conn) {
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
func main() {

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
			log.Fatalln(fmt.Printf("Dial INTO local service error: %s", err))
		}

		client, err := listener.Accept()
		if err != nil {
			log.Fatalln(err)
		}

		handleClient(client, local)
	}

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
