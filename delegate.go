// Copyright 2021 SPRogster
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	cnilibrary "github.com/containernetworking/cni/libcni"
	"github.com/containernetworking/cni/pkg/invoke"
	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	current "github.com/containernetworking/cni/pkg/types/100"
	"github.com/containernetworking/cni/pkg/version"

	bv "github.com/containernetworking/plugins/pkg/utils/buildversion"
)

func init() {
	// this ensures that main runs only on main thread (thread group leader).
	// since namespace ops (unshare, setns) are done for a single thread, we
	// must ensure that the goroutine does not jump from OS thread to thread
	runtime.LockOSThread()
}

type NetConf struct {
	types.NetConf
	DefaultInterface     string   `json:"defaultInterface"`
	AdditionalInterfaces []string `json:"additionalInterfaces"`
	ConfDir              string   `json:"confDir"`
	AdditionalPrefix     string   `json:"additionalPrefix"`
}

const defaultInterfacePrefix = "multi"

type iface struct {
	conf   *cnilibrary.NetworkConfig
	done   bool
	ifName string
}

var pluginsPaths = map[string]string{}

func loadCniConfs(confDir string, names []string) (map[string]*iface, error) {
	files, err := cnilibrary.ConfFiles(confDir, []string{".conf", ".json"})
	switch {
	case err != nil:
		return nil, fmt.Errorf("failed to detect CNI config file: %v", err)
	case len(files) == 0:
		return nil, fmt.Errorf("no CNI network config found in %s", confDir)
	}

	res := make(map[string]*iface, len(names))
	for _, name := range names {
		res[name] = nil
	}

	count := 0

	for _, filename := range files {
		conf, err := cnilibrary.ConfFromFile(filename)
		if err != nil {
			return nil, fmt.Errorf("failed to load CNI config file %s: %v", filename, err)
		}

		name := conf.Network.Name

		if v, needed := res[name]; v != nil {
			return nil, fmt.Errorf("duplicate config for CNI network %s found in `%s`", name, confDir)
		} else if needed {
			res[name] = &iface{
				conf: conf,
				done: false,
			}
			count++
		}
	}

	if count != len(names) {
		for name, v := range res {
			if v == nil {
				return nil, fmt.Errorf("some CNI networks not found, one is %s", name)
			}
		}
	}

	return res, nil
}

func fillNames(ifaces map[string]*iface, defname string, conf NetConf) {
	ifaces[conf.DefaultInterface].ifName = defname
	for i, name := range conf.AdditionalInterfaces {
		ifaces[name].ifName = fmt.Sprintf("%s%d", conf.AdditionalPrefix, i)
	}
}

func fillPluginsPaths(ifaces map[string]*iface) error {
	exec := &invoke.RawExec{Stderr: os.Stderr}

	paths := filepath.SplitList(os.Getenv("CNI_PATH"))

	for name, i := range ifaces {
		plugin := i.conf.Network.Type
		if _, exists := pluginsPaths[plugin]; exists {
			continue
		}

		path, err := exec.FindInPath(plugin, paths)
		if err != nil {
			return fmt.Errorf("unable to find plugin (%s) path: %s", name, err)
		}

		pluginsPaths[plugin] = path
	}

	return nil
}

func createInterfaces(cniConfs map[string]*iface, conf NetConf, parsedArgs *skel.CmdArgs) (*current.Result, error) {
	var res types.Result
	var err error

	defNet := cniConfs[conf.DefaultInterface]
	args := &invoke.Args{
		Command:     "ADD",
		ContainerID: parsedArgs.ContainerID,
		NetNS:       parsedArgs.Netns,
		IfName:      parsedArgs.IfName,
		Path:        parsedArgs.Path,
	}

	res, err = invoke.ExecPluginWithResult(context.TODO(), pluginsPaths[defNet.conf.Network.Type], defNet.conf.Bytes, args, nil)
	if err != nil {
		return nil, fmt.Errorf("default interface creation failed: %s", err)
	}
	cniConfs[conf.DefaultInterface].done = true

	defer func() {
		if err != nil {
			for _, v := range cniConfs {
				if v.done {
					// TODO possible resources leak message
					_ = invoke.DelegateDel(context.TODO(), v.conf.Network.Type, v.conf.Bytes, nil)
				}
			}
		}
	}()

	result, err2 := current.NewResultFromResult(res)
	if err2 != nil {
		return nil, fmt.Errorf("failed to convert result to current version: %s", err2)
	}

	for name, v := range cniConfs {
		if !v.done {
			args.IfName = v.ifName

			res, err = invoke.ExecPluginWithResult(context.TODO(), pluginsPaths[v.conf.Network.Type], v.conf.Bytes, args, nil)
			if err != nil {
				return nil, fmt.Errorf("error creating interface (%s): %s", name, err)
			}
			cniConfs[name].done = true

			curRes, err2 := current.NewResultFromResult(res)
			if err2 != nil {
				return nil, fmt.Errorf("interface (%s) creation failed: %s", name, err)
			}
			mergeResults(curRes, result)
		}
	}

	// TODO dns

	return result, nil
}

func destroyInterfaces(cniConfs map[string]*iface, conf NetConf, parsedArgs *skel.CmdArgs) error {
	args := &invoke.Args{
		Command:     "DEL",
		ContainerID: parsedArgs.ContainerID,
		NetNS:       parsedArgs.Netns,
		Path:        parsedArgs.Path,
	}

	for name, v := range cniConfs {
		args.IfName = v.ifName

		err := invoke.ExecPluginWithoutResult(context.TODO(), pluginsPaths[v.conf.Network.Type], v.conf.Bytes, args, nil)
		if err != nil {
			return fmt.Errorf("error deleting interface (%s): %s", name, err)
		}
	}

	return nil
}

func mergeResults(curRes *current.Result, result *current.Result) {
	if curRes.Interfaces != nil && len(curRes.Interfaces) != 0 {
		if result.Interfaces == nil && len(result.Interfaces) == 0 {
			result.Interfaces = curRes.Interfaces
		} else {
			result.Interfaces = append(result.Interfaces, curRes.Interfaces...)
		}
	}
	if curRes.IPs != nil && len(curRes.IPs) != 0 {
		if result.IPs == nil && len(result.IPs) == 0 {
			result.IPs = curRes.IPs
		} else {
			result.IPs = append(result.IPs, curRes.IPs...)
		}
	}
	if curRes.Routes != nil && len(curRes.Routes) != 0 {
		if result.Routes == nil && len(result.Routes) == 0 {
			result.Routes = curRes.Routes
		} else {
			result.Routes = append(result.Routes, curRes.Routes...)
		}
	}
	// TODO dns
}

func cmdAdd(args *skel.CmdArgs) error {
	conf := NetConf{}

	if err := json.Unmarshal(args.StdinData, &conf); err != nil {
		return fmt.Errorf("failed to load netconf: %v", err)
	}
	if conf.AdditionalPrefix == "" {
		conf.AdditionalPrefix = defaultInterfacePrefix
	}

	names := append(conf.AdditionalInterfaces, conf.DefaultInterface)
	cniConfs, err := loadCniConfs(conf.ConfDir, names)
	if err != nil {
		return err
	}

	fillNames(cniConfs, args.IfName, conf)

	if err := fillPluginsPaths(cniConfs); err != nil {
		return err
	}

	res, err := createInterfaces(cniConfs, conf, args)
	if err != nil {
		return fmt.Errorf("interfaces creation failure: %s", err)
	}

	return types.PrintResult(res, conf.CNIVersion)
}

func cmdDel(args *skel.CmdArgs) error {
	conf := NetConf{}
	if err := json.Unmarshal(args.StdinData, &conf); err != nil {
		return fmt.Errorf("failed to load netconf: %v", err)
	}

	if conf.AdditionalPrefix == "" {
		conf.AdditionalPrefix = defaultInterfacePrefix
	}

	names := append(conf.AdditionalInterfaces, conf.DefaultInterface)
	cniConfs, err := loadCniConfs(conf.ConfDir, names)
	if err != nil {
		return err
	}

	fillNames(cniConfs, args.IfName, conf)

	if err := fillPluginsPaths(cniConfs); err != nil {
		return err
	}

	err = destroyInterfaces(cniConfs, conf, args)

	return err
}

func main() {
	skel.PluginMain(cmdAdd, cmdCheck, cmdDel, version.All, bv.BuildString("multi"))
}

func cmdCheck(args *skel.CmdArgs) error {
	return nil
}
