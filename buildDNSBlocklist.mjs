#!/usr/bin/env node
import { writeFile } from 'fs/promises'
import { URL } from 'url'
import axios from 'axios'
import { extract } from 'tar-stream'
import { Readable } from 'stream'
import gunzip from "gunzip-maybe"

process.on('uncaughtException', (err) => {
  console.error(err)
  process.exit(1)
})

process.on('unhandledRejection', (err) => {
  console.error(err)
  process.exit(2)
})

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
  'https://raw.githubusercontent.com/StevenBlack/hosts/master/data/StevenBlack/hosts',
  'https://raw.githubusercontent.com/Sekhan/TheGreatWall/master/TheGreatWall.txt',
  'https://raw.githubusercontent.com/dibdot/DoH-IP-blocklists/master/doh-domains.txt',
  'https://dsi.ut-capitole.fr/blacklists/download/ads.tar.gz',
  'https://dsi.ut-capitole.fr/blacklists/download/aggressive.tar.gz',
  'https://dsi.ut-capitole.fr/blacklists/download/audio-video.tar.gz',
  'https://dsi.ut-capitole.fr/blacklists/download/bitcoin.tar.gz',
  'https://dsi.ut-capitole.fr/blacklists/download/chat.tar.gz',
  'https://dsi.ut-capitole.fr/blacklists/download/astrology.tar.gz',
  'https://dsi.ut-capitole.fr/blacklists/download/blog.tar.gz',
  'https://dsi.ut-capitole.fr/blacklists/download/cryptojacking.tar.gz',
  'https://dsi.ut-capitole.fr/blacklists/download/dangerous_material.tar.gz',
  'https://dsi.ut-capitole.fr/blacklists/download/dating.tar.gz',
  'https://dsi.ut-capitole.fr/blacklists/download/ddos.tar.gz',
  'https://dsi.ut-capitole.fr/blacklists/download/dialer.tar.gz',
  'https://dsi.ut-capitole.fr/blacklists/download/doh.tar.gz',
  'https://dsi.ut-capitole.fr/blacklists/download/download.tar.gz',
  'https://dsi.ut-capitole.fr/blacklists/download/drogue.tar.gz',
  'https://dsi.ut-capitole.fr/blacklists/download/filehosting.tar.gz',
  'https://dsi.ut-capitole.fr/blacklists/download/forums.tar.gz',
  'https://dsi.ut-capitole.fr/blacklists/download/gambling.tar.gz',
  'https://dsi.ut-capitole.fr/blacklists/download/games.tar.gz',
  'https://dsi.ut-capitole.fr/blacklists/download/hacking.tar.gz',
  'https://dsi.ut-capitole.fr/blacklists/download/lingerie.tar.gz',
  'https://dsi.ut-capitole.fr/blacklists/download/malware.tar.gz',
  'https://dsi.ut-capitole.fr/blacklists/download/manga.tar.gz',
  'https://dsi.ut-capitole.fr/blacklists/download/mixed_adult.tar.gz',
  'https://dsi.ut-capitole.fr/blacklists/download/phishing.tar.gz',
  'https://dsi.ut-capitole.fr/blacklists/download/proxy.tar.gz',
  'https://dsi.ut-capitole.fr/blacklists/download/publicite.tar.gz',
  'https://dsi.ut-capitole.fr/blacklists/download/radio.tar.gz',
  'https://dsi.ut-capitole.fr/blacklists/download/redirector.tar.gz',
  'https://dsi.ut-capitole.fr/blacklists/download/remote-control.tar.gz',
  'https://dsi.ut-capitole.fr/blacklists/download/shortener.tar.gz',
  'https://dsi.ut-capitole.fr/blacklists/download/sexual_education.tar.gz',
  'https://dsi.ut-capitole.fr/blacklists/download/social_networks.tar.gz',
  'https://dsi.ut-capitole.fr/blacklists/download/stalkerware.tar.gz',
  'https://dsi.ut-capitole.fr/blacklists/download/strict_redirector.tar.gz',
  'https://dsi.ut-capitole.fr/blacklists/download/tricheur.tar.gz',
  'https://dsi.ut-capitole.fr/blacklists/download/vpn.tar.gz',
  'https://dsi.ut-capitole.fr/blacklists/download/violence.tar.gz',
  'https://dsi.ut-capitole.fr/blacklists/download/warez.tar.gz',
  'https://dsi.ut-capitole.fr/blacklists/download/webmail.tar.gz',
  'https://dsi.ut-capitole.fr/blacklists/download/adult.tar.gz'
]


function extractUT1DomainFileFromGzipStream(resp) {
  // will be a domains entry
  // if we find it replace resp.data with the plain text version
  // if we don't find it, leave as is
  return new Promise((resolve) => {
    const extractStream = extract()
    const tarGzStream = typeof resp.data === 'string' ? Readable.from(Buffer.from(resp.data)) : Readable.from(resp.data)
    let foundDomains = false
    extractStream.on('entry', (header, stream, next) => {
      if(header.name.endsWith('domains')) {
        const chunks = []
        stream.on('data', (chunk) => chunks.push(chunk))
        stream.on('end', () => {
          resp.data = Buffer.concat(chunks).toString('utf8')
          foundDomains = true
          next()
        })
      } else {
        next()
      }
    })
    extractStream.on('end', () => {
      next()
    })
    extractStream.on('error', (err) => {
      console.error(err)
    })
    extractStream.on('finish', () => {
      if(!foundDomains) {
        resp.data = ''
        console.warn(`Failed to extract domain list form ${resp.headers}`)
      }
      resolve(resp)
    })
    tarGzStream.pipe(gunzip()).pipe(extractStream)
  })
}

const requests = urls.map((url) => axios.get(url, {
  decompress: !url.endsWith('tar.gz'),
  responseType: url.endsWith('tar.gz') ? 'arraybuffer' : 'text'
}).then((resp) => {
  if (resp.headers['content-type'] === 'application/x-gzip' || typeof resp.data !== 'string') {
    return extractUT1DomainFileFromGzipStream(resp)
  } else {
    return resp
  }
}).catch((err) => {
  console.error(err)
  process.exit(3)
}))

const responses = await Promise.all(requests).catch((err) => {
  console.error(err)
  process.exit(1)
})

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
