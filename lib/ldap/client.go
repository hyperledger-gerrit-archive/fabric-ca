/*
Copyright IBM Corp. 2016 All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

		 http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package ldap

import (
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/pkg/errors"

	"github.com/Knetic/govaluate"
	"github.com/cloudflare/cfssl/log"
	"github.com/hyperledger/fabric-ca/api"
	"github.com/hyperledger/fabric-ca/lib/spi"
	ctls "github.com/hyperledger/fabric-ca/lib/tls"
	"github.com/hyperledger/fabric-ca/util"
	"github.com/hyperledger/fabric/bccsp"
	ldap "gopkg.in/ldap.v2"
)

var (
	errNotSupported = errors.New("Not supported")
	ldapURLRegex    = regexp.MustCompile("ldaps*://(\\S+):(\\S+)@")
)

// Config is the configuration object for this LDAP client
type Config struct {
	Enabled     bool   `def:"false" help:"Enable the LDAP client for authentication and attributes"`
	URL         string `help:"LDAP client URL of form ldap://adminDN:adminPassword@host[:port]/base" mask:"url"`
	UserFilter  string `def:"(uid=%s)" help:"The LDAP user filter to use when searching for users"`
	GroupFilter string `def:"(memberUid=%s)" help:"The LDAP group filter for a single affiliation group"`
	Attribute   AttrConfig
	TLS         ctls.ClientTLSConfig
}

// AttrConfig is attribute configuration information
type AttrConfig struct {
	Names      []string    `help:"The names of LDAP attributes to request on an LDAP search"`
	Converters []Converter `help:"Converters from LDAP attributes to fabric CA attributes"`
}

// Converter converts an LDAP attribute to a fabric CA attribute
type Converter struct {
	Name  string `help:"The name of a fabric CA attribute"`
	Value string `help:"The expression to evaluate in order to obtain the value of the fabric CA attribute"`
}

// Implements Stringer interface for ldap.Config
// Calls util.StructToString to convert the Config struct to
// string.
func (c Config) String() string {
	return util.StructToString(&c)
}

// NewClient creates an LDAP client
func NewClient(cfg *Config, csp bccsp.BCCSP) (*Client, error) {
	log.Debugf("Creating new LDAP client for %+v", cfg)
	if cfg == nil {
		return nil, errors.New("LDAP configuration is nil")
	}
	if cfg.URL == "" {
		return nil, errors.New("LDAP configuration requires a 'URL'")
	}
	u, err := url.Parse(cfg.URL)
	if err != nil {
		return nil, err
	}
	var defaultPort string
	switch u.Scheme {
	case "ldap":
		defaultPort = "389"
	case "ldaps":
		defaultPort = "636"
	default:
		return nil, errors.Errorf("Invalid LDAP scheme: %s", u.Scheme)
	}
	var host, port string
	if strings.Index(u.Host, ":") < 0 {
		host = u.Host
		port = defaultPort
	} else {
		host, port, err = net.SplitHostPort(u.Host)
		if err != nil {
			return nil, errors.Wrapf(err, "Invalid LDAP host:port (%s)", u.Host)
		}
	}
	portVal, err := strconv.Atoi(port)
	if err != nil {
		return nil, errors.Wrapf(err, "Invalid LDAP port (%s)", port)
	}
	c := new(Client)
	c.Host = host
	c.Port = portVal
	c.UseSSL = u.Scheme == "ldaps"
	if u.User != nil {
		c.AdminDN = u.User.Username()
		c.AdminPassword, _ = u.User.Password()
	}
	c.Base = u.Path
	if c.Base != "" && strings.HasPrefix(c.Base, "/") {
		c.Base = c.Base[1:]
	}
	c.UserFilter = cfgVal(cfg.UserFilter, "(uid=%s)")
	c.GroupFilter = cfgVal(cfg.GroupFilter, "(memberUid=%s)")
	c.attrNames = cfg.Attribute.Names
	c.attrExprs = map[string]*userExpr{}
	for _, converter := range cfg.Attribute.Converters {
		attrName := converter.Name
		ue, err := newUserExpr(attrName, converter.Value)
		if err != nil {
			return nil, err
		}
		c.attrExprs[converter.Name] = ue
		log.Debugf("Added LDAP mapping expression for attribute '%s'", attrName)
	}
	c.TLS = &cfg.TLS
	c.CSP = csp
	log.Debug("LDAP client was successfully created")
	return c, nil
}

func cfgVal(val1, val2 string) string {
	if val1 != "" {
		return val1
	}
	return val2
}

// Client is an LDAP client
type Client struct {
	Host          string
	Port          int
	UseSSL        bool
	AdminDN       string
	AdminPassword string
	Base          string
	UserFilter    string               // e.g. "(uid=%s)"
	GroupFilter   string               // e.g. "(memberUid=%s)"
	attrNames     []string             // Names of attributes to request on an LDAP search
	attrExprs     map[string]*userExpr // Expressions to evaluate to get attribute value
	AdminConn     *ldap.Conn
	TLS           *ctls.ClientTLSConfig
	CSP           bccsp.BCCSP
}

// GetUser returns a user object for username and attribute values
// for the requested attribute names
func (lc *Client) GetUser(username string, attrNames []string) (spi.User, error) {

	var sresp *ldap.SearchResult
	var err error

	log.Debugf("Getting user '%s'", username)

	// Search for the given username
	sreq := ldap.NewSearchRequest(
		lc.Base, ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf(lc.UserFilter, username),
		lc.attrNames,
		nil,
	)

	// Try to search using the cached connection, if there is one
	conn := lc.AdminConn
	if conn != nil {
		log.Debugf("Searching for user '%s' using cached connection", username)
		sresp, err = conn.Search(sreq)
		if err != nil {
			log.Debugf("LDAP search failed but will close connection and try again; error was: %s", err)
			conn.Close()
			lc.AdminConn = nil
		}
	}

	// If there was no cached connection or the search failed for any reason
	// (including because the server may have closed the cached connection),
	// try with a new connection.
	if sresp == nil {
		log.Debugf("Searching for user '%s' using new connection", username)
		conn, err = lc.newConnection()
		if err != nil {
			return nil, err
		}
		sresp, err = conn.Search(sreq)
		if err != nil {
			conn.Close()
			return nil, errors.Wrapf(err, "LDAP search failure; search request: %+v", sreq)
		}
		// Cache the connection
		lc.AdminConn = conn
	}

	// Make sure there was exactly one match found
	if len(sresp.Entries) < 1 {
		return nil, errors.Errorf("User '%s' does not exist in LDAP directory", username)
	}
	if len(sresp.Entries) > 1 {
		return nil, errors.Errorf("Multiple users with name '%s' exist in LDAP directory", username)
	}

	entry := sresp.Entries[0]
	if entry == nil {
		return nil, errors.Errorf("No entry was returned for user '%s'", username)
	}

	// Construct the user object
	user := &user{
		name:   username,
		entry:  entry,
		client: lc,
	}

	log.Debugf("Successfully retrieved user '%s', DN: %s", username, entry.DN)

	return user, nil
}

// InsertUser inserts a user
func (lc *Client) InsertUser(user spi.UserInfo) error {
	return errNotSupported
}

// UpdateUser updates a user
func (lc *Client) UpdateUser(user spi.UserInfo) error {
	return errNotSupported
}

// DeleteUser deletes a user
func (lc *Client) DeleteUser(id string) error {
	return errNotSupported
}

// GetAffiliation returns an affiliation group
func (lc *Client) GetAffiliation(name string) (spi.Affiliation, error) {
	return nil, errNotSupported
}

// GetRootAffiliation returns the root affiliation group
func (lc *Client) GetRootAffiliation() (spi.Affiliation, error) {
	return nil, errNotSupported
}

// InsertAffiliation adds an affiliation group
func (lc *Client) InsertAffiliation(name string, prekey string) error {
	return errNotSupported
}

// DeleteAffiliation deletes an affiliation group
func (lc *Client) DeleteAffiliation(name string) error {
	return errNotSupported
}

// Connect to the LDAP server and bind as user as admin user as specified in LDAP URL
func (lc *Client) newConnection() (conn *ldap.Conn, err error) {
	address := fmt.Sprintf("%s:%d", lc.Host, lc.Port)
	if !lc.UseSSL {
		log.Debug("Connecting to LDAP server over TCP")
		conn, err = ldap.Dial("tcp", address)
		if err != nil {
			return conn, errors.Wrapf(err, "Failed to connect to LDAP server over TCP at %s", address)
		}
	} else {
		log.Debug("Connecting to LDAP server over TLS")
		tlsConfig, err2 := ctls.GetClientTLSConfig(lc.TLS, lc.CSP)
		if err2 != nil {
			return nil, errors.WithMessage(err2, "Failed to get client TLS config")
		}

		tlsConfig.ServerName = lc.Host

		conn, err = ldap.DialTLS("tcp", address, tlsConfig)
		if err != nil {
			return conn, errors.Wrapf(err, "Failed to connect to LDAP server over TLS at %s", address)
		}
	}
	// Bind with a read only user
	if lc.AdminDN != "" && lc.AdminPassword != "" {
		log.Debugf("Binding to the LDAP server as admin user %s", lc.AdminDN)
		err := conn.Bind(lc.AdminDN, lc.AdminPassword)
		if err != nil {
			return nil, errors.Wrapf(err, "LDAP bind failure as %s", lc.AdminDN)
		}
	}
	return conn, nil
}

// A user represents a single user or identity from LDAP
type user struct {
	name   string
	entry  *ldap.Entry
	client *Client
}

// GetName returns the user's enrollment ID, which is the DN (Distinquished Name)
func (u *user) GetName() string {
	return u.entry.DN
}

// GetType returns the type of the user
func (u *user) GetType() string {
	return "client"
}

// GetMaxEnrollments returns the max enrollments of the user
func (u *user) GetMaxEnrollments() int {
	return 0
}

// Login logs a user in using password
func (u *user) Login(password string, caMaxEnrollment int) error {

	// Get a connection to use to bind over as the user to check the password
	conn, err := u.client.newConnection()
	if err != nil {
		return err
	}
	defer conn.Close()

	// Bind calls the LDAP server to check the user's password
	err = conn.Bind(u.entry.DN, password)
	if err != nil {
		return errors.Wrapf(err, "LDAP authentication failure for user '%s' (DN=%s)", u.name, u.entry.DN)
	}

	return nil

}

// LoginComplete requires no action on LDAP
func (u *user) LoginComplete() error {
	return nil
}

// GetAffiliationPath returns the affiliation path for this user.
// We convert the OU hierarchy to an array of strings, orderered
// from top-to-bottom.
func (u *user) GetAffiliationPath() []string {
	dn := u.entry.DN
	path := []string{}
	parts := strings.Split(dn, ",")
	for i := len(parts) - 1; i >= 0; i-- {
		p := parts[i]
		if strings.HasPrefix(p, "OU=") {
			path = append(path, strings.Trim(p[3:], " "))
		}
	}
	log.Debugf("Affilation path for DN '%s' is '%+v'", dn, path)
	return path
}

// GetAttribute returns the value of an attribute, or "" if not found
func (u *user) GetAttribute(name string) (*api.Attribute, error) {
	expr := u.client.attrExprs[name]
	if expr == nil {
		log.Debugf("Getting attribute '%s' from LDAP user '%s'", name, u.name)
		return &api.Attribute{Name: name, Value: u.entry.GetAttributeValue(name)}, nil
	}
	log.Debugf("Evaluating expression for attribute '%s' from LDAP user '%s'", name, u.name)
	value, err := expr.evaluate(u)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to evaluate LDAP expression")
	}
	return &api.Attribute{Name: name, Value: fmt.Sprintf("%v", value)}, nil
}

// GetAttributes returns the requested attributes
func (u *user) GetAttributes(attrNames []string) ([]api.Attribute, error) {
	var attrs []api.Attribute
	if attrNames == nil {
		for _, name := range u.client.attrNames {
			attr, err := u.GetAttribute(name)
			if err != nil {
				return nil, err
			}
			attrs = append(attrs, *attr)
		}
		for name := range u.client.attrExprs {
			attr, err := u.GetAttribute(name)
			if err != nil {
				return nil, err
			}
			attrs = append(attrs, *attr)
		}
	}
	return attrs, nil
}

// Revoke is not supported for LDAP
func (u *user) Revoke() error {
	return errNotSupported
}

// Returns a slice with the elements reversed
func reverse(in []string) []string {
	size := len(in)
	out := make([]string, size)
	for i := 0; i < size; i++ {
		out[i] = in[size-i-1]
	}
	return out
}

func newUserExpr(attr, expr string) (*userExpr, error) {
	ue := &userExpr{attr: attr, expr: expr}
	err := ue.parse()
	if err != nil {
		return nil, err
	}
	return ue, nil
}

type userExpr struct {
	attr, expr string
	eval       *govaluate.EvaluableExpression
	user       *user
}

func (ue *userExpr) parse() error {
	eval, err := govaluate.NewEvaluableExpression(ue.expr)
	if err == nil {
		// We were able to parse 'expr' without reference to any defined
		// functions, so we can reuse this evaluator across multiple users.
		ue.eval = eval
		return nil
	}
	// Try to parse 'expr' with defined functions
	_, err = govaluate.NewEvaluableExpressionWithFunctions(ue.expr, ue.functions())
	if err != nil {
		return errors.Wrapf(err, "Invalid expression for attribute '%s'", ue.attr)
	}
	return nil
}

func (ue *userExpr) evaluate(user *user) (interface{}, error) {
	var err error
	parms := map[string]interface{}{
		"DN":          user.entry.DN,
		"affiliation": user.GetAffiliationPath(),
	}
	eval := ue.eval
	if eval == nil {
		ue2 := &userExpr{
			attr: ue.attr,
			expr: ue.expr,
			user: user,
		}
		eval, err = govaluate.NewEvaluableExpressionWithFunctions(ue.expr, ue2.functions())
		if err != nil {
			return nil, errors.Wrapf(err, "Invalid expression for attribute '%s'", ue.attr)
		}
	}
	result, err := eval.Evaluate(parms)
	if err != nil {
		log.Debugf("Error evaluating expression for attribute '%s'; parms: %+v; error: %+v", ue.attr, parms, err)
		return nil, err
	}
	log.Debugf("Evaluated expression for attribute '%s'; parms: %+v; result: %+v", ue.attr, parms, result)
	return result, nil
}

func (ue *userExpr) functions() map[string]govaluate.ExpressionFunction {
	return map[string]govaluate.ExpressionFunction{
		"attr": ue.attrFunction,
		"if":   ue.ifFunction,
	}
}

// Get an LDAP attribute's value.
// The usage is:
//     attrFunction <attrName> [<separator>]
// If attribute <attrName> has multiple values, return the values in a single
// string separated by the <separator> string, which is a comma by default.
// Example:
//    Assume attribute "foo" has two values "bar1" and "bar2".
//    attrFunction("foo") returns "bar1,bar2"
//    attrFunction("foo",":") returns "bar1:bar2"
func (ue *userExpr) attrFunction(args ...interface{}) (interface{}, error) {
	if len(args) < 1 || len(args) > 2 {
		return nil, fmt.Errorf("Expecting 1 or 2 arguments for 'attr' but found %d", len(args))
	}
	attrName, ok := args[0].(string)
	if !ok {
		return nil, errors.Errorf("First argument to 'attr' must be a string; '%s' is not a string", args[0])
	}
	sep := ","
	if len(args) == 2 {
		sep, ok = args[1].(string)
		if !ok {
			return nil, errors.Errorf("Second argument to 'attr' must be a string; '%s' is not a string", args[1])
		}
	}
	vals := ue.user.entry.GetAttributeValues(attrName)
	if len(vals) == 0 {
		return nil, fmt.Errorf("No value for attribute '%s'", attrName)
	}
	return strings.Join(vals, sep), nil
}

// If function
func (ue *userExpr) ifFunction(args ...interface{}) (interface{}, error) {
	if len(args) != 3 {
		return nil, fmt.Errorf("Expecting 3 arguments for 'if' but found %d", len(args))
	}
	cond, ok := args[0].(bool)
	if !ok {
		return nil, errors.New("Expecting first argument to 'if' to be a boolean")
	}
	if cond {
		return args[1], nil
	}
	return args[2], nil
}
