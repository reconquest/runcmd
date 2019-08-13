package runcmd

import (
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/reconquest/karma-go"
	"golang.org/x/crypto/ssh"
)

var sshSignals = map[os.Signal]ssh.Signal{
	syscall.Signal(1):  ssh.SIGHUP,
	syscall.Signal(2):  ssh.SIGINT,
	syscall.Signal(3):  ssh.SIGQUIT,
	syscall.Signal(4):  ssh.SIGILL,
	syscall.Signal(6):  ssh.SIGABRT,
	syscall.Signal(8):  ssh.SIGFPE,
	syscall.Signal(9):  ssh.SIGKILL,
	syscall.Signal(11): ssh.SIGSEGV,
	syscall.Signal(13): ssh.SIGPIPE,
	syscall.Signal(14): ssh.SIGALRM,
	syscall.Signal(15): ssh.SIGTERM,
}

// RemoteCmd is implementation of CmdWorker interface for remote commands
type RemoteCmd struct {
	args         []string
	session      *ssh.Session
	sessionError error
	connection   *timeBoundedConnection
	client       *ssh.Client
	timeout      *Timeout
}

// Remote is implementation of Runner interface for remote commands
type Remote struct {
	client     *ssh.Client
	connection *timeBoundedConnection
	timeout    *Timeout
}

// Timeout is struct for setting various timeout for ssh connection
type Timeout struct {
	Connection time.Duration
	Send       time.Duration
	Receive    time.Duration
	KeepAlive  time.Duration
}

type timeBoundedConnection struct {
	net.Conn
	readTimeout  time.Duration
	writeTimeout time.Duration
}

func (connection *timeBoundedConnection) Read(p []byte) (int, error) {
	if connection.readTimeout != 0 {
		err := connection.Conn.SetReadDeadline(time.Now().Add(
			connection.readTimeout,
		))
		if err != nil {
			return 0, err
		}
	}

	return connection.Conn.Read(p)
}

func (connection *timeBoundedConnection) Write(p []byte) (int, error) {
	if connection.writeTimeout != 0 {
		err := connection.Conn.SetWriteDeadline(time.Now().Add(
			connection.writeTimeout,
		))
		if err != nil {
			return 0, err
		}
	}

	return connection.Conn.Write(p)
}

func NewRemoteRawKeyAuthRunner(
	user, host, key string, timeout Timeout,
) (*Remote, error) {
	signer, err := ssh.ParsePrivateKey([]byte(key))
	if err != nil {
		return nil, karma.Format(
			err,
			"unable to parse private ssh key",
		)
	}

	return NewRemoteRunner(
		user,
		host,
		[]ssh.AuthMethod{ssh.PublicKeys(signer)},
		timeout,
	)
}

func NewRemotePasswordAuthRunner(
	user, host, password string,
	timeout Timeout,
) (*Remote, error) {
	return NewRemoteRunner(
		user,
		host,
		[]ssh.AuthMethod{ssh.Password(password)},
		timeout,
	)
}

func NewRemoteRunner(
	user, host string,
	auth []ssh.AuthMethod,
	timeout Timeout,
) (*Remote, error) {
	config := &ssh.ClientConfig{
		User:            user,
		Auth:            auth,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	dialer := net.Dialer{
		Timeout:   timeout.Connection,
		KeepAlive: timeout.KeepAlive,
	}

	if timeout.Connection != 0 {
		dialer.Deadline = time.Now().Add(timeout.Connection)
	}

	conn, err := dialer.Dial("tcp", host)
	if err != nil {
		return nil, err
	}

	connection := &timeBoundedConnection{
		Conn: conn,
	}

	// We need to temporary switch on timeout to prevent hanging
	// on IO operations if server is successfully connected by TCP
	// but give no response.
	connection.readTimeout = timeout.Send
	connection.writeTimeout = timeout.Receive

	sshConnection, channels, requests, err := ssh.NewClientConn(
		connection, host, config,
	)
	if err != nil {
		return nil, err
	}

	connection.readTimeout = 0
	connection.writeTimeout = 0

	return &Remote{
		client:     ssh.NewClient(sshConnection, channels, requests),
		connection: connection,
		timeout:    &timeout,
	}, nil
}

// Command creates worker for current command execution
func (remote *Remote) Command(name string, arg ...string) CmdWorker {
	session, err := remote.client.NewSession()
	if err != nil {
		err = karma.Format(
			err, "can't create ssh session",
		)
	}

	return &RemoteCmd{
		args:         append([]string{name}, arg...),
		connection:   remote.connection,
		timeout:      remote.timeout,
		client:       remote.client,
		session:      session,
		sessionError: err,
	}
}

// CloseConnection is method for closing ssh connection of current runner
func (remote *Remote) CloseConnection() error {
	return remote.client.Close()
}

func (remote *RemoteCmd) CmdError() error {
	return remote.sessionError
}

// Run executes current command
func (cmd *RemoteCmd) Run() error {
	return run(cmd)
}

func (cmd *RemoteCmd) Output() ([]byte, []byte, error) {
	return output(cmd)
}

// Start begins current command execution
func (cmd *RemoteCmd) Start() error {
	if cmd.sessionError != nil {
		return cmd.sessionError
	}

	cmd.initTimeout()

	args := []string{}
	for _, arg := range cmd.args {
		args = append(args, escapeCommandArgumentStrict(arg))
	}

	return cmd.session.Start(strings.Join(args, " "))
}

// Wait returns error after command execution if current command return nonzero
// exit code
func (cmd *RemoteCmd) Wait() (err error) {
	defer func() {
		closeErr := cmd.session.Close()
		if err == nil && closeErr != nil {
			if closeErr.Error() != "EOF" {
				err = karma.Format(
					err, "can't close ssh session",
				)
			}
		}
	}()

	return cmd.session.Wait()
}

// StdinPipe returns stdin of current worker
func (cmd *RemoteCmd) StdinPipe() (io.WriteCloser, error) {
	if cmd.sessionError != nil {
		return nil, cmd.sessionError
	}

	return cmd.session.StdinPipe()
}

// StdoutPipe returns stdout of current worker
func (cmd *RemoteCmd) StdoutPipe() (io.Reader, error) {
	if cmd.sessionError != nil {
		return nil, cmd.sessionError
	}

	return cmd.session.StdoutPipe()
}

// StderrPipe returns stderr of current worker
func (cmd *RemoteCmd) StderrPipe() (io.Reader, error) {
	if cmd.sessionError != nil {
		return nil, cmd.sessionError
	}

	return cmd.session.StderrPipe()
}

// SetStdout is method for binding your own writer to worker stdout
func (cmd *RemoteCmd) SetStdout(buffer io.Writer) {
	cmd.session.Stdout = buffer
}

// SetStderr is method for binding your own writer to worker stderr
func (cmd *RemoteCmd) SetStderr(buffer io.Writer) {
	cmd.session.Stderr = buffer
}

func (cmd *RemoteCmd) SetStdin(buffer io.Reader) {
	cmd.session.Stdin = buffer
}

// GetArgs returns cmdline for current worker
func (cmd *RemoteCmd) GetArgs() []string {
	return cmd.args
}

func (cmd *RemoteCmd) initTimeout() {
	if cmd.connection == nil {
		return
	}
	cmd.connection.readTimeout = cmd.timeout.Send
	cmd.connection.writeTimeout = cmd.timeout.Receive
}

// Signal sends specified ssh represnetation of os signal into existing ssh
// session
func (cmd *RemoteCmd) Signal(signal syscall.Signal) error {
	sshSignal, ok := sshSignals[signal]
	if !ok {
		return errors.New("unexpected ssh signal")
	}

	return cmd.session.Signal(sshSignal)
}

func escapeCommandArgumentStrict(argument string) string {
	escaper := strings.NewReplacer(
		`\`, `\\`,
		"`", "\\`",
		`"`, `\"`,
		`$`, `\$`,
	)

	argument = escaper.Replace(argument)

	return `"` + argument + `"`
}
