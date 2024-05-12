#!/usr/bin/env node
import { writeFile } from 'fs/promises'
import axios from 'axios'

const bigList = await axios.get('https://big.oisd.nl/dnsmasq')
const youtube = await axios.get('https://raw.githubusercontent.com/gieljnssns/Social-media-Blocklists/master/pihole-youtube.txt')

const lines = bigList.data.split('\n').concat(youtube.data.split('\n'))
const blocked = new Set()
for(const line of lines) {
    if(line[0] !== '#') {
        blocked.add(line)
    }
}
let blockList = ''
for(let key of blocked) {
    key = key.replace('server=/', '')
    key = key.replace('/', '')
    blockList += key + '\n'
}

await writeFile('dns.txt', blockList)