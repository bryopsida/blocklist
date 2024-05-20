#!/usr/bin/env node
import { writeFile } from 'fs/promises'
import axios from 'axios'
import ipaddr from 'ipaddr.js'
import IPCIDR from 'ip-cidr'
import { Address6 } from 'ip-address'

const feeds = [
  'https://www.myip.ms/files/blacklist/csf/latest_blacklist.txt',
  'https://www.spamhaus.org/drop/dropv6.txt'
]

const requests = feeds.map((url) => axios.get(url))
const responses = await Promise.all(requests)

function isValid (input) {
  try {
    const parsedAddress = ipaddr.parse(input)
    if (parsedAddress.kind() === 'ipv6') return true
  } catch (_ignored) {}
  try {
    if (IPCIDR.isValidCIDR(input) || IPCIDR.isValidAddress(input)) {
      const address = new Address6(input)
      return address.isCorrect() && !address.is4()
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
  return input.split(';')[0].trim()
}

function filterComments (input) {
  return !input.startsWith('#') && input !== ''
}

const ips = responses.map((r) => r.data.split('\n')).flat()
  .filter(filterComments)
  .map(normalize)
  .filter(isValid)
  .filter(ignoreDups)
  .sort()
  .join('\n')

await writeFile('ipv6.txt', ips, {
  enconding: 'utf8'
})
