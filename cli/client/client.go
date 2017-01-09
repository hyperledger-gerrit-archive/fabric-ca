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

package client

import (
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/cloudflare/cfssl/cli"

	_ "github.com/go-sql-driver/mysql" // import to support MySQL
	_ "github.com/lib/pq"              // import to support Postgres
	_ "github.com/mattn/go-sqlite3"    // import to support SQLite3
)

var cmdName string

// Config is a type to hold flag values used by client commands.
type Config struct {
	ConfigFile string
}

// usage is the cfssl usage heading. It will be appended with names of defined commands in cmds
// to form the final usage message of cfssl.
const usage = `Usage:
Available commands:
`

// printDefaultValue is a helper function to print out a user friendly
// usage message of a flag. It's useful since we want to write customized
// usage message on selected subsets of the global flag set. It is
// borrowed from standard library source code. Since flag value type is
// not exported, default string flag values are printed without
// quotes. The only exception is the empty string, which is printed as "".
func printDefaultValue(f *flag.Flag) {
	format := "  -%s=%s: %s\n"
	if f.DefValue == "" {
		format = "  -%s=%q: %s\n"
	}
	fmt.Fprintf(os.Stderr, format, f.Name, f.DefValue, f.Usage)
}

// Command are the client commands
func Command() error {
	cmds := map[string]*cli.Command{
		"register": RegisterCommand,
		"enroll":   EnrollCommand,
		"reenroll": ReenrollCommand,
		"revoke":   RevokeCommand,
	}

	err := parseFlags(cmds)
	if err != nil {
		return err
	}

	return nil
}

func parseFlags(cmds map[string]*cli.Command) error {
	var clientFlagSet = flag.NewFlagSet("client", flag.ExitOnError)
	var c cli.Config

	regFlags(&c, clientFlagSet)
	flag.Parse()

	// Initial parse of command line arguments. By convention, only -h/-help is supported.
	if flag.Usage == nil {
		flag.Usage = func() {
			fmt.Fprintf(os.Stderr, usage)
			for name := range cmds {
				fmt.Fprintf(os.Stderr, "\t%s\n", name)
			}
			fmt.Fprintf(os.Stderr, "Top-level flags:\n")
			flag.PrintDefaults()
		}
	}

	if flag.NArg() < 1 {
		fmt.Fprintf(os.Stderr, "No command is given.\n")
		flag.Usage()
		return errors.New("No command was given")
	}

	// Clip out the command name and args for the command
	cmdName = flag.Arg(0)
	args := flag.Args()[1:]

	cmd, found := cmds[cmdName]
	if !found {
		fmt.Fprintf(os.Stderr, "Command %s is not defined.\n", cmdName)
		flag.Usage()
		return errors.New("undefined command")
	}

	cmd.Flags = append(cmd.Flags, "loglevel")

	clientFlagSet.Usage = func() {
		fmt.Fprintf(os.Stderr, "\t%s", cmd.UsageText)
		for _, name := range cmd.Flags {
			if f := clientFlagSet.Lookup(name); f != nil {
				printDefaultValue(f)
			}
		}
	}

	// Parse all flags and take the rest as argument lists for the command
	clientFlagSet.Parse(args)
	args = clientFlagSet.Args()

	if err := cmd.Main(args, c); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return err
	}

	return nil
}

// regFlags defines all client command flags and associates their values with variables.
func regFlags(c *cli.Config, f *flag.FlagSet) {
	f.StringVar(&c.ConfigFile, "config", "", "path to configuration file")
}
