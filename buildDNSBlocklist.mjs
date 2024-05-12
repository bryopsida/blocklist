#!/usr/bin/env node
import { writeFile } from 'fs/promises'
import axios from 'axios'

const bigList = await axios.get('https://big.oisd.nl/dnsmasq')
const youtube = await axios.get('https://raw.githubusercontent.com/gieljnssns/Social-media-Blocklists/master/pihole-youtube.txt')
const facebook = await axios.get('https://raw.githubusercontent.com/gieljnssns/Social-media-Blocklists/master/adguard-facebook.txt')
const tiktok = await axios.get('https://raw.githubusercontent.com/gieljnssns/Social-media-Blocklists/master/adguard-tiktok.txt')
const reddit = await axios.get('https://raw.githubusercontent.com/gieljnssns/Social-media-Blocklists/master/adguard-reddit.txt')
const twitch = await axios.get('https://raw.githubusercontent.com/gieljnssns/Social-media-Blocklists/master/adguard-twitch.txt')
const snapchat = await axios.get('https://raw.githubusercontent.com/gieljnssns/Social-media-Blocklists/master/adguard-snapchat.txt')
const whatsapp = await axios.get('https://raw.githubusercontent.com/gieljnssns/Social-media-Blocklists/master/adguard-whatsapp.txt')
const instagram = await axios.get('https://raw.githubusercontent.com/gieljnssns/Social-media-Blocklists/master/adguard-instagram.txt')
const twitter = await axios.get('https://raw.githubusercontent.com/gieljnssns/Social-media-Blocklists/master/adguard-twitter.txt')

const responses = [bigList, youtube, facebook, tiktok, reddit, twitch, snapchat, whatsapp, instagram, twitter]

const lines = responses.map((resp) => resp.data.split('\n')).flat()
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
    key = key.replace('||', '')
    key = key.replace('^', '')
    blockList += key + '\n'
}

await writeFile('dns.txt', blockList)