#!/usr/bin/env node
import { writeFile } from 'fs/promises'
import { URL } from 'url'
import axios from 'axios'

function isValidUrl (s) {
  try {
    new URL(`https://${s}`)
    return true
  } catch (err) {
    return false
  }
};

const urls = [
  'https://big.oisd.nl/dnsmasq',
  'https://raw.githubusercontent.com/gieljnssns/Social-media-Blocklists/master/pihole-youtube.txt',
  'https://raw.githubusercontent.com/gieljnssns/Social-media-Blocklists/master/pihole-youtube.txt',
  'https://raw.githubusercontent.com/gieljnssns/Social-media-Blocklists/master/adguard-facebook.txt',
  'https://raw.githubusercontent.com/gieljnssns/Social-media-Blocklists/master/adguard-tiktok.txt',
  'https://raw.githubusercontent.com/gieljnssns/Social-media-Blocklists/master/adguard-reddit.txt',
  'https://raw.githubusercontent.com/gieljnssns/Social-media-Blocklists/master/adguard-twitch.txt',
  'https://raw.githubusercontent.com/gieljnssns/Social-media-Blocklists/master/adguard-snapchat.txt',
  'https://raw.githubusercontent.com/gieljnssns/Social-media-Blocklists/master/adguard-whatsapp.txt',
  'https://raw.githubusercontent.com/gieljnssns/Social-media-Blocklists/master/adguard-instagram.txt',
  'https://raw.githubusercontent.com/gieljnssns/Social-media-Blocklists/master/adguard-twitter.txt',
  'https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts',
  'https://adaway.org/hosts.txt',
  'https://v.firebog.net/hosts/AdguardDNS.txt',
  'https://v.firebog.net/hosts/Easyprivacy.txt',
  'https://bitbucket.org/ethanr/dns-blacklists/raw/8575c9f96e5b4a1308f2f12394abd86d0927a4a0/bad_lists/Mandiant_APT1_Report_Appendix_D.txt',
  'https://raw.githubusercontent.com/DandelionSprout/adfilt/master/Alternate%20versions%20Anti-Malware%20List/AntiMalwareHosts.txt',
  'https://osint.digitalside.it/Threat-Intel/lists/latestdomains.txt',
  'https://blocklistproject.github.io/Lists/alt-version/ads-nl.txt',
  'https://blocklistproject.github.io/Lists/alt-version/abuse-nl.txt',
  'https://blocklistproject.github.io/Lists/alt-version/malware-nl.txt',
  'https://blocklistproject.github.io/Lists/alt-version/tracking-nl.txt',
  'https://blocklistproject.github.io/Lists/alt-version/phishing-nl.txt',
  'https://blocklistproject.github.io/Lists/alt-version/scam-nl.txt',
  'https://blocklistproject.github.io/Lists/alt-version/ransomware-nl.txt',
  'https://blocklistproject.github.io/Lists/alt-version/ransomware-nl.txt',
  'https://raw.githubusercontent.com/stamparm/aux/master/maltrail-malware-domains.txt',
  'https://threatfox.abuse.ch/downloads/hostfile/',
  'https://raw.githubusercontent.com/StevenBlack/hosts/master/data/StevenBlack/hosts'
]

const requests = urls.map((url) => axios.get(url))

const responses = await Promise.all(requests)

const lines = responses.map((resp) => resp.data.split('\n')).flat()
const blocked = new Set()

const excludedLines = [
  '0.0.0.0 0.0.0.0',
  '127.0.0.1 localhost',
  '127.0.0.1 localhost.localdomain',
  '127.0.0.1 local',
  '255.255.255.255 broadcasthost',
  '::1 localhost',
  '::1 ip6-localhost',
  '::1 ip6-loopback',
  'fe80::1%lo0 localhost',
  'ff00::0 ip6-localnet',
  'ff00::0 ip6-mcastprefix',
  'ff02::1 ip6-allnodes',
  'ff02::2 ip6-allrouters',
  'ff02::3 ip6-allhosts',
  '=',
  '::1'
]

const cantStartWith = [
  '#',
  '!#',
  '!',
  'if-a-large-hosts-file-contains-this-entry-then-it'
]

const stripPatterns = ['server=/', '/', '||', '^', '0.0.0.0', '127.0.0.1']

for (const line of lines) {
  if (!cantStartWith.some((blockedPrefix) => line.startsWith(blockedPrefix)) && !excludedLines.some((ele) => ele === line)) {
    blocked.add(line)
  }
}
let blockList = ''
let blockedNormalizedHosts = []
for (let key of blocked) {
  for (const removePattern of stripPatterns) {
    key = key.replace(removePattern, '')
  }

  key = key.trim()
  key = key.split(' ')[0]
  if (isValidUrl(key)) {
    blockedNormalizedHosts.push(key)
  } else {
    console.warn(`${key} is not a valid url! Dropping from list!`)
  }
}
blockedNormalizedHosts = blockedNormalizedHosts.sort()
for (const blockedHost of blockedNormalizedHosts) {
  blockList += blockedHost + '\n'
}

await writeFile('dns.txt', blockList)
