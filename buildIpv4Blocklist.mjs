#!/usr/bin/env node
import { writeFile } from 'fs/promises'
import axios from 'axios'
import ipaddr from 'ipaddr.js'
import IPCIDR from 'ip-cidr'
import { Address4 } from 'ip-address'

const feeds = [
  'https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt',
  'https://sslbl.abuse.ch/blacklist/sslipblacklist.txt',
  'https://cinsarmy.com/list/ci-badguys.txt',
  'https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt',
  'https://rules.emergingthreats.net/blockrules/compromised-ips.txt',
  'https://isc.sans.edu/block.txt',
  'https://www.spamhaus.org/drop/drop.txt',
  'https://www.spamhaus.org/drop/edrop.txt',
  // 'https://talosintelligence.com/documents/ip-blacklist',
  'https://reputation.alienvault.com/reputation.snort',
  'https://blocklist.greensnow.co/greensnow.txt',
  'https://www.maxmind.com/en/high-risk-ip-sample-list',
  'https://www.binarydefense.com/banlist.txt',
  'https://www.projecthoneypot.org/list_of_ips.php?t=b'
]

const requests = feeds.map((url) => axios.get(url, {
  decompress: true,
  headers: {
    'accept-encoding': 'gzip,deflate'
  }
}))
const responses = await Promise.all(requests)

function isValid (input) {
  try {
    const parsedAddress = ipaddr.parse(input)
    if (parsedAddress.kind() === 'ipv4') return true
  } catch (_ignored) {}
  try {
    if (IPCIDR.isValidCIDR(input) || IPCIDR.isValidAddress(input)) {
      const address = new Address4(input)
      return address.isCorrect()
    }
    return false
  } catch (_ignored) {
    return false
  }
}

const ipSet = new Set()

function ignoreDups (input) {
  if (ipSet.has(input)) {
    return false
  } else {
    ipSet.add(input)
    return true
  }
}

function normalize (input) {
  const firstPass = input.split(';')[0].trim()
  // check if it's tab delimited
  const secondPass = firstPass.split('\t')
  if (secondPass.length === 7) {
    return `${secondPass[0]}/${secondPass[2]}`
  }
  const thirdPass = firstPass.split('#')[0].trim()
  return thirdPass
}

function filterComments (input) {
  return !input.startsWith('#') && input !== ''
}

const ips = responses.map((r) => r.data.split('\n')).flat()
  .filter(filterComments)
  .map(normalize)
  .filter((s) => s !== '')
  .filter(isValid)
  .filter(ignoreDups)
  .sort()
  .join('\n')

await writeFile('ipv4.txt', ips, {
  enconding: 'utf8'
})
