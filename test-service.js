#!/usr/bin/env node

const { performance } = require('perf_hooks'); // Node.js performance API
const http = require('http'); // Node.js native HTTP module

const DOMAINS = [
    // real domains
    "google.com",
    "microsoft.com",
    "apple.com",
    "amazon.com",
    "facebook.com",
    "salesforce.com",
    "ibm.com",
    "oracle.com",
    "adobe.com",
    "spotify.com",
    "twitter.com",
    "linkedin.com",
    "netflix.com",
    "airbnb.com",
    "uber.com",
    "slack.com",
    "zoom.us",
    "github.com",
    "dropbox.com",
    "atlassian.com",

    // fake domains
    "alphanode.cloud",
    "gigabytecraft.tech",
    "cloudstack.io",
    "corsair-systems.com",
    "cybermatrix24.dev",
    "dataforge.tech",
    "deltacloud.org",
    "ethereality.co",
    "fusion-tech.lol",
    "hypermail.io",
    "infinitymailing.io",
    "nexusmail.net",
    "novacorp.co",
    "omnisphere.co",
    "pulse-networks.org",
    "quantumhost.cloud",
    "stellarcloud.net",
    "synthetica.dev",
    "vertex-systems.dev",
    "zenithmail.io",
];

const TARGET = "spf.protection.outlook.com";
const BASE_URL = "http://localhost:8080/api/v1/check-spf";

async function checkSpf(domain) {
    const start = performance.now();
    const url = `${BASE_URL}?domain=${domain}&target=${TARGET}`;

    return new Promise((resolve) => {
        http.get(url, (response) => {
            const duration = (performance.now() - start).toFixed(2);
            let data = '';

            response.on('data', (chunk) => {
                data += chunk;
            });

            response.on('end', () => {
                const jsonData = JSON.parse(data);
                if (response.statusCode > 299) {
                    console.log(`${domain}: ${duration}ms (error: ${jsonData.error})`);
                } else {
                    console.log(`${domain}: ${duration}ms (reported: ${jsonData.elapsed_ms ?? '-'}) - Found: ${jsonData.found ?? '-'} (checked ${jsonData.checked_domains ?? 'no'} domains)`);
                }
                resolve();
            });
        }).on('error', (error) => {
            console.error(`Error checking ${domain}: ${error.message}`);
            resolve(); // Resolve the promise even if there's an error
        });
    });
}

console.log(`Testing parallel SPF checks for target: ${TARGET}\n`);

// Execute all checks in parallel
Promise.all(DOMAINS.map(domain => checkSpf(domain)))
    .then(() => console.log("\nAll checks completed"))
    .catch(error => console.error("Error during execution:", error));
