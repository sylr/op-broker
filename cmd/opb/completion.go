package main

import (
	"maps"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sylr/op-broker/internal/client"
	"github.com/sylr/op-broker/internal/ref"
)

// Completions come from the configuration file: the broker has no listing
// API, so the references, vaults and items offered are those of the bundles.
// Completion never fails loudly: a missing or invalid file offers nothing.

// completionConfig returns the configuration, or nil if it cannot be loaded.
func (g *globals) completionConfig() *client.Config {
	cfg, err := g.config()
	if err != nil {
		return nil
	}
	return cfg
}

func (g *globals) completeContexts(_ *cobra.Command, _ []string, toComplete string) ([]cobra.Completion, cobra.ShellCompDirective) {
	cfg := g.completionConfig()
	if cfg == nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	var comps []cobra.Completion
	for _, name := range slices.Sorted(maps.Keys(cfg.Contexts)) {
		if strings.HasPrefix(name, toComplete) {
			comps = append(comps, cobra.CompletionWithDesc(name, cfg.Contexts[name].Server))
		}
	}
	return comps, cobra.ShellCompDirectiveNoFileComp
}

// completeContextArg completes the single context name argument of context
// show and context use.
func (g *globals) completeContextArg(cmd *cobra.Command, args []string, toComplete string) ([]cobra.Completion, cobra.ShellCompDirective) {
	if len(args) > 0 {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	return g.completeContexts(cmd, args, toComplete)
}

func (g *globals) completeServers(_ *cobra.Command, _ []string, toComplete string) ([]cobra.Completion, cobra.ShellCompDirective) {
	var comps []cobra.Completion
	if cfg := g.completionConfig(); cfg != nil {
		for _, name := range slices.Sorted(maps.Keys(cfg.Contexts)) {
			if s := cfg.Contexts[name].Server; strings.HasPrefix(s, toComplete) && !slices.Contains(comps, s) {
				comps = append(comps, s)
			}
		}
	}
	return comps, cobra.ShellCompDirectiveNoFileComp
}

func (g *globals) completeBrokers(_ *cobra.Command, _ []string, toComplete string) ([]cobra.Completion, cobra.ShellCompDirective) {
	var brokers []string
	if cfg := g.completionConfig(); cfg != nil {
		for _, c := range cfg.Contexts {
			if c.Broker != "" && !slices.Contains(brokers, c.Broker) {
				brokers = append(brokers, c.Broker)
			}
		}
	}
	var comps []cobra.Completion
	for _, b := range slices.Sorted(slices.Values(brokers)) {
		if strings.HasPrefix(b, toComplete) {
			comps = append(comps, b)
		}
	}
	if len(comps) > 0 {
		return comps, cobra.ShellCompDirectiveNoFileComp
	}
	// Nothing configured matches: help with the identity syntax.
	for _, p := range []cobra.Completion{
		cobra.CompletionWithDesc("user:", "untagged node of a user"),
		cobra.CompletionWithDesc("tag:", "node with an ACL tag"),
		cobra.CompletionWithDesc("node:", "node stable ID"),
	} {
		if strings.HasPrefix(p[:strings.IndexByte(p, '\t')], toComplete) {
			comps = append(comps, p)
		}
	}
	return comps, cobra.ShellCompDirectiveNoFileComp | cobra.ShellCompDirectiveNoSpace
}

// completeBundles completes bundle names not in chosen. Once a chosen bundle
// pins a context, bundles pinned to another context are left out, since they
// cannot be combined.
func (g *globals) completeBundles(chosen []string, toComplete string) ([]cobra.Completion, cobra.ShellCompDirective) {
	cfg := g.completionConfig()
	if cfg == nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	var pin string
	for _, name := range chosen {
		if b, ok := cfg.Bundles[name]; ok && b.Context != "" {
			pin = b.Context
		}
	}
	var comps []cobra.Completion
	for _, name := range slices.Sorted(maps.Keys(cfg.Bundles)) {
		b := cfg.Bundles[name]
		if slices.Contains(chosen, name) || !strings.HasPrefix(name, toComplete) {
			continue
		}
		if pin != "" && b.Context != "" && b.Context != pin {
			continue
		}
		var vars []string
		for _, e := range b.Env {
			vars = append(vars, e.Name)
		}
		desc := strings.Join(vars, ", ")
		if b.Context != "" {
			desc = "[" + b.Context + "] " + desc
		}
		comps = append(comps, cobra.CompletionWithDesc(name, desc))
	}
	return comps, cobra.ShellCompDirectiveNoFileComp
}

// bundleRefs returns the parsed references of the bundles with the bundle
// and variable that use them, in a stable order.
func bundleRefs(cfg *client.Config) (refs []ref.Ref, raw []string, uses []string) {
	for _, name := range slices.Sorted(maps.Keys(cfg.Bundles)) {
		for _, e := range cfg.Bundles[name].Env {
			r, err := ref.Parse(e.Ref)
			if err != nil || slices.Contains(raw, e.Ref) {
				continue
			}
			refs, raw, uses = append(refs, r), append(raw, e.Ref), append(uses, name+": "+e.Name)
		}
	}
	return refs, raw, uses
}

func (g *globals) completeRefs(_ *cobra.Command, args []string, toComplete string) ([]cobra.Completion, cobra.ShellCompDirective) {
	if len(args) > 0 {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	var comps []cobra.Completion
	if cfg := g.completionConfig(); cfg != nil {
		_, raw, uses := bundleRefs(cfg)
		for i, s := range raw {
			if strings.HasPrefix(s, toComplete) {
				comps = append(comps, cobra.CompletionWithDesc(s, uses[i]))
			}
		}
		slices.Sort(comps)
	}
	if len(comps) == 0 && strings.HasPrefix("op://", toComplete) {
		return []cobra.Completion{"op://"}, cobra.ShellCompDirectiveNoFileComp | cobra.ShellCompDirectiveNoSpace
	}
	return comps, cobra.ShellCompDirectiveNoFileComp
}

func (g *globals) completeVaults(_ *cobra.Command, _ []string, toComplete string) ([]cobra.Completion, cobra.ShellCompDirective) {
	var comps []cobra.Completion
	if cfg := g.completionConfig(); cfg != nil {
		refs, _, _ := bundleRefs(cfg)
		for _, r := range refs {
			if strings.HasPrefix(r.Vault, toComplete) && !slices.Contains(comps, r.Vault) {
				comps = append(comps, r.Vault)
			}
		}
	}
	slices.Sort(comps)
	return comps, cobra.ShellCompDirectiveNoFileComp
}

// completeItems completes the items of vault, or of every vault if it is
// not set yet, found in the bundles.
func (g *globals) completeItems(vault, toComplete string) ([]cobra.Completion, cobra.ShellCompDirective) {
	var comps []cobra.Completion
	if cfg := g.completionConfig(); cfg != nil {
		refs, _, _ := bundleRefs(cfg)
		var seen []string
		for _, r := range refs {
			if vault != "" && !strings.EqualFold(r.Vault, vault) {
				continue
			}
			if strings.HasPrefix(r.Item, toComplete) && !slices.Contains(seen, r.Item) {
				seen = append(seen, r.Item)
				comps = append(comps, cobra.CompletionWithDesc(r.Item, "vault "+r.Vault))
			}
		}
	}
	return comps, cobra.ShellCompDirectiveNoFileComp
}
