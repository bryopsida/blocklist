# What is this?

This repo aggregates a IP and DNS block lists and updates them on a schedule

The script is run via this [npm script](https://github.com/bryopsida/blocklist/blob/ab6130c3352883dedfcc998386c5fffdedb34c83/package.json#L7)
and the workflow schedule is set [here](https://raw.githubusercontent.com/bryopsida/blocklist/main/.github/workflows/update.yml). 

The repository history is perodicially squashed as well to keep the repo size from getting out of hand.

## How do I use this?

You can use the dns block list with something like adguard, pihole, or a unbound dns block list.

Due to file size limits on github the DNS block list is fragmented into 4 pieces all of which need to be added to your block list to get the complete list.

There are also ip block lists [ipv4](https://raw.githubusercontent.com/bryopsida/blocklist/main/ipv4.txt), [ipv6](https://raw.githubusercontent.com/bryopsida/blocklist/main/ipv6.txt).
These can be fetched and loaded into a firewall ruleset as an alias to deny egress/ingress to any IPs on the list. 


## Can I add items to the lists?

If you wish to add items to the lists you can submit a PR, the things being blocked must either be a constant list with an explanation for why it should be blocked, or by an addition to the scripts to pull a block list from a reputable source.
