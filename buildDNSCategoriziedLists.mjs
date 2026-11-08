#!/usr/bin/env node
import { createWriteStream } from 'node:fs'
import { URL } from 'node:url'
import axios from 'axios'
import { extract } from 'tar-stream'
import { Readable } from 'node:stream'
import gunzip from "gunzip-maybe"
import randomUserAgent from 'random-useragent'
import { safeDomains } from './safeDomains.mjs'


process.on('uncaughtException', (err) => {
  console.error(err)
  process.exit(1)
})

process.on('unhandledRejection', (err) => {
  console.error(err)
  process.exit(2)
})

function isValidUrl(s) {
  try {
    new URL(`https://${s}`)
    return true
  } catch (err) {
    return false
  }
}

// Grouped feeds structured into specific blocklist categories
const categories = [
  {
    name: 'ads',
    urls: [
        'https://dsi.ut-capitole.fr/blacklists/download/ads.tar.gz',
    ]
  },
  {
    name: 'aggressive',
    urls: [
        'https://dsi.ut-capitole.fr/blacklists/download/aggressive.tar.gz',
    ]
  },
  {
    name: 'adult_content',
    urls: [
        'https://dsi.ut-capitole.fr/blacklists/download/adult.tar.gz'
    ]
  },
  {
    name: 'audio_video',
    urls: [
        'https://dsi.ut-capitole.fr/blacklists/download/audio-video.tar.gz',
    ]
  },
  {
    name: 'games',
    urls: [
        'https://dsi.ut-capitole.fr/blacklists/download/games.tar.gz',
    ]
  },
  {
    name: 'malware',
    urls: [
        'https://dsi.ut-capitole.fr/blacklists/download/malware.tar.gz',
    ]
  },
  {
    name: 'phishing',
    urls: [
        'https://dsi.ut-capitole.fr/blacklists/download/phishing.tar.gz',
    ]
  },
  {
    name: 'proxy',
    urls: [
        'https://dsi.ut-capitole.fr/blacklists/download/proxy.tar.gz',
    ]
  },
  {
    name: 'vpn',
    urls: [
        'https://dsi.ut-capitole.fr/blacklists/download/vpn.tar.gz',
    ]
  },
  {
    name: 'warez',
    urls: [
        'https://dsi.ut-capitole.fr/blacklists/download/warez.tar.gz',
    ]
  },
  {
    name: 'cryptojacking',
    urls: [
        'https://dsi.ut-capitole.fr/blacklists/download/cryptojacking.tar.gz',
    ]
  },
  {
    name: 'dangerous_material',
    urls: [
        'https://dsi.ut-capitole.fr/blacklists/download/dangerous_material.tar.gz',
    ]
  },
  {
    name: 'dating',
    urls: [
        'https://dsi.ut-capitole.fr/blacklists/download/dating.tar.gz',
    ]
  },
  {
    name: 'ddos',
    urls: [
        'https://dsi.ut-capitole.fr/blacklists/download/ddos.tar.gz',
    ]
  },
  {
    name: 'dialer',
    urls: [
        'https://dsi.ut-capitole.fr/blacklists/download/dialer.tar.gz',
    ]
  },
  {
    name: 'doh',
    urls: [
        'https://dsi.ut-capitole.fr/blacklists/download/doh.tar.gz',
    ]
  },
  {
    name: 'download',
    urls: [
        'https://dsi.ut-capitole.fr/blacklists/download/download.tar.gz',
    ]
  },
  {
    name: 'drogue',
    urls: [
        'https://dsi.ut-capitole.fr/blacklists/download/drogue.tar.gz',
    ]
  },
  {
    name: 'filehosting',
    urls: [
        'https://dsi.ut-capitole.fr/blacklists/download/filehosting.tar.gz',
    ]
  },
  {
    name: 'forums',
    urls: [
        'https://dsi.ut-capitole.fr/blacklists/download/forums.tar.gz',
    ]
  },
  {
    name: 'gambling',
    urls: [
        'https://dsi.ut-capitole.fr/blacklists/download/gambling.tar.gz',
    ]
  },
  {
    name: 'hacking',
    urls: [
        'https://dsi.ut-capitole.fr/blacklists/download/hacking.tar.gz',
    ]
  },
  {
    name: 'lingerie',
    urls: [
        'https://dsi.ut-capitole.fr/blacklists/download/lingerie.tar.gz',
    ]
  },
  {
    name: 'manga',
    urls: [
        'https://dsi.ut-capitole.fr/blacklists/download/manga.tar.gz',
    ]
  },
  {
    name: 'mixed_adult',
    urls: [
        'https://dsi.ut-capitole.fr/blacklists/download/mixed_adult.tar.gz',
    ]
  },
  {
    name: 'publicite',
    urls: [
        'https://dsi.ut-capitole.fr/blacklists/download/publicite.tar.gz',
    ]
  },
  {
    name: 'radio',
    urls: [
        'https://dsi.ut-capitole.fr/blacklists/download/radio.tar.gz',
    ]
  },
  {
    name: 'redirector',
    urls: [
        'https://dsi.ut-capitole.fr/blacklists/download/redirector.tar.gz',
    ]
  },
  {
    name: 'remote-control',
    urls: [
        'https://dsi.ut-capitole.fr/blacklists/download/remote-control.tar.gz',
    ]
  },
  {
    name: 'shortener',
    urls: [
        'https://dsi.ut-capitole.fr/blacklists/download/shortener.tar.gz',
    ]
  },
  {
    name: 'sexual_education', 
    urls: [
        'https://dsi.ut-capitole.fr/blacklists/download/sexual_education.tar.gz',
    ]
  },
  {
    name: 'social_networks',
    urls: [
        'https://dsi.ut-capitole.fr/blacklists/download/social_networks.tar.gz',
    ]
  },
  {
    name: 'stalkerware',
    urls: [
        'https://dsi.ut-capitole.fr/blacklists/download/stalkerware.tar.gz',
    ]
  },
  {
    name: 'strict_redirector',
    urls: [
        'https://dsi.ut-capitole.fr/blacklists/download/strict_redirector.tar.gz',
    ]
  },
  {
    name: 'tricheur',
    urls: [
        'https://dsi.ut-capitole.fr/blacklists/download/tricheur.tar.gz',
    ]
  },
  {
    name: 'violence',
    urls: [
        'https://dsi.ut-capitole.fr/blacklists/download/violence.tar.gz',
    ]
  },
  {
    name: 'webmail',
    urls: [
        'https://dsi.ut-capitole.fr/blacklists/download/webmail.tar.gz',
    ]
  }
] 

function extractUT1DomainFileFromGzipStream(resp) {
  return new Promise((resolve) => {
    const extractStream = extract()
    const tarGzStream = typeof resp.data === 'string' ? Readable.from(Buffer.from(resp.data)) : Readable.from(resp.data)
    let foundDomains = false
    
    extractStream.on('entry', (header, stream, next) => {
      if (header.name.endsWith('domains')) {
        const chunks = []
        stream.on('data', (chunk) => chunks.push(chunk))
        stream.on('end', () => {
          resp.data = Buffer.concat(chunks).toString('utf8')
          foundDomains = true
          next()
        })
      } else {
        stream.resume()
        next()
      }
    })
    
    extractStream.on('error', (err) => {
      console.error(err)
    })
    
    extractStream.on('finish', () => {
      if (!foundDomains) {
        resp.data = ''
      }
      resolve(resp)
    })
    
    tarGzStream.pipe(gunzip()).pipe(extractStream)
  })
}

const excludedLines = [
  '0.0.0.0 0.0.0.0', '127.0.0.1 localhost', '127.0.0.1 localhost.localdomain',
  '127.0.0.1 local', '255.255.255.255 broadcasthost', '::1 localhost',
  '::1 ip6-localhost', '::1 ip6-loopback', 'fe80::1%lo0 localhost',
  'ff00::0 ip6-localnet', 'ff00::0 ip6-mcastprefix', 'ff02::1 ip6-allnodes',
  'ff02::2 ip6-allrouters', 'ff02::3 ip6-allhosts', '=', '::1'
]
const safeDomains = ['graduacion.unir.net']
const cantStartWith = ['#', '!#', '!', 'if-a-large-hosts-file-contains-this-entry-then-it']
const stripPatterns = ['server=/', '/', '||', '^', '0.0.0.0', '127.0.0.1']

function processRawData(rawData, domainSet) {
  const rawLines = rawData.split('\n')
  
  for (let line of rawLines) {
    line = line.trim()
    if (!line) continue
    
    const isExcludedLineFormat = excludedLines.some((ele) => ele === line)
    const isSafeDomain = safeDomains.some((ele) => line.endsWith(ele))
    
    if (!cantStartWith.some((blockedPrefix) => line.startsWith(blockedPrefix)) && !isExcludedLineFormat && !isSafeDomain) {
      for (const removePattern of stripPatterns) {
        line = line.replace(removePattern, '')
      }
      line = line.trim().split(' ')[0]
      if (isValidUrl(line)) {
        domainSet.add(line)
      }
    }
  }
}

const MAX_FILE_SIZE = 50 * 1024 * 1024 // 50MB

async function writeCategoryFiles(categoryName, domainList) {
  let fileIndex = 1
  let currentSize = 0
  let fileStream = createWriteStream(`${categoryName}_${fileIndex}.txt`)
  
  for (const domain of domainList) {
    const lineBuffer = Buffer.from(domain + '\n', 'utf8')
    
    if (currentSize + lineBuffer.length > MAX_FILE_SIZE && currentSize > 0) {
      fileStream.end()
      fileIndex++
      currentSize = 0
      fileStream = createWriteStream(`${categoryName}_${fileIndex}.txt`)
    }
    
    fileStream.write(lineBuffer)
    currentSize += lineBuffer.length
  }
  fileStream.end()
}

// Process each category block independently for standalone functionality
for (const category of categories) {
  console.log(`Processing category: ${category.name}`)
  const categoryDomains = new Set()
  
  for (const url of category.urls) {
    try {
      const resp = await axios.get(url, {
        headers: { 'User-Agent': randomUserAgent.getRandom() },
        decompress: false,
        responseType: 'arraybuffer'
      })
      
      const extractedResp = await extractUT1DomainFileFromGzipStream(resp)
      if (!extractedResp.data) continue
      
      processRawData(extractedResp.data, categoryDomains)
      
    } catch (err) {
      console.error(`Failed to process feed inside ${category.name}:`, err.message)
    }
  }
  
  if (categoryDomains.size > 0) {
    const sortedDomains = Array.from(categoryDomains).sort()
    await writeCategoryFiles(category.name, sortedDomains)
    console.log(`Finished ${category.name}. Total domains: ${categoryDomains.size}`)
  } else {
    console.log(`No domains found or extracted for category: ${category.name}`)
  }
}