/*
 * SPDX-License-Identifier: Apache-2.0
 */

const { connect, Identity, Signer, hash, signers } = require('@hyperledger/fabric-gateway');
const grpc = require('@grpc/grpc-js');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { TextDecoder } = require('util');


// Constants for your network configuration
const channelName = 'forensic-channel';
const chaincodeName = 'forensicContract';
const mspId = 'Org1MSP';

// File paths for crypto materials for different roles
const cryptoPath = path.resolve(__dirname, '..', 'fabric-samples', 'test-network', 'organizations', 'peerOrganizations', 'org1.example.com');
const monitoringCertPath = path.resolve(cryptoPath, 'users', 'MonitoringTeam@org1.example.com', 'msp', 'signcerts', 'cert.pem');
const monitoringKeyDirectoryPath = path.resolve(cryptoPath, 'users', 'MonitoringTeam@org1.example.com', 'msp', 'keystore');

const forensicCertPath = path.resolve(cryptoPath, 'users', 'ForensicInvestigator@org1.example.com', 'msp', 'signcerts', 'cert.pem');
const forensicKeyDirectoryPath = path.resolve(cryptoPath, 'users', 'ForensicInvestigator@org1.example.com', 'msp', 'keystore');

const evidenceCollectorCertPath = path.resolve(cryptoPath, 'users', 'EvidenceCollector@org1.example.com', 'msp', 'signcerts', 'cert.pem');
const evidenceCollectorKeyDirectoryPath = path.resolve(cryptoPath, 'users', 'EvidenceCollector@org1.example.com', 'msp', 'keystore');

const judgeCertPath = path.resolve(cryptoPath, 'users', 'Judge@org1.example.com', 'msp', 'signcerts', 'cert.pem');
const judgeKeyDirectoryPath = path.resolve(cryptoPath, 'users', 'Judge@org1.example.com', 'msp', 'keystore');

const tlsCertPath = path.resolve(cryptoPath, 'peers', 'peer0.org1.example.com', 'tls', 'ca.crt');
const peerEndpoint = 'localhost:7051';
const peerHostAlias = 'peer0.org1.example.com';

// Create a UTF-8 text decoder for parsing chaincode responses
const utf8Decoder = new TextDecoder();

// Load TLS certificate
const tlsCert = fs.readFileSync(tlsCertPath);
const tlsCredentials = grpc.credentials.createSsl(tlsCert);

let ipfs;

 

// Modified main function to log roles when initializing and using contracts
async function main() {
    try {

        // Dynamically import IPFS and create an instance
        const { create } = await import('ipfs-core');
        ipfs = await create({ repo: 'ok' + Math.random() });

        // Use Monitoring Team credentials for initializing incident and log role
        console.log('\n--- Using Monitoring Team Credentials ---');
        const monitoringContract = await createContract(monitoringCertPath, monitoringKeyDirectoryPath, 'Monitoring Team');
        await initializeIncident(monitoringContract);

        // Use Evidence Collector credentials for submitting evidence and log role
        console.log('\n--- Using Evidence Collector Credentials ---');
        const evidenceContract = await createContract(evidenceCollectorCertPath, evidenceCollectorKeyDirectoryPath, 'Evidence Collector');
        await submitEvidence(evidenceContract);

        // Use Forensic Investigator credentials for retrieving evidence
        console.log('\n--- Using Forensic Investigator Credentials ---');
        const forensicContract = await createContract(forensicCertPath, forensicKeyDirectoryPath, 'Forensic Investigator');
        await retrieveAndVerifyEvidence(forensicContract, 'Forensic Investigator');

        // Use Judge credentials for retrieving evidence
        console.log('\n--- Using Judge Credentials ---');
        const judgeContract = await createContract(judgeCertPath, judgeKeyDirectoryPath, 'Judge');
        await retrieveAndVerifyEvidence(judgeContract, 'Judge');

         // Call the function to create a forensic report
         await createForensicReport(forensicContract);


    } finally {
        // Stop the IPFS node
        if (ipfs) {
            await ipfs.stop();
        }
    }
}

// Function to create a contract connection and log user role and details
async function createContract(certPath, keyDirectoryPath, role) {
    const { client, gateway, identity } = await setupClient(certPath, keyDirectoryPath);
    const network = gateway.getNetwork(channelName);
    const contract = network.getContract(chaincodeName);

    // Log the user details and role
    console.log(`\n--- Using ${role} Credentials ---`);
    console.log(`MSP ID: ${identity.mspId}`);
    console.log(`Certificate Path: ${certPath}`);
    console.log(`Key Directory Path: ${keyDirectoryPath}`);

    return contract;
}

// Helper function to set up client, identity, and gateway with logging
async function setupClient(certPath, keyDirectoryPath) {
    const certificate = fs.readFileSync(certPath).toString();
    const privateKeyPem = fs.readFileSync(path.join(keyDirectoryPath, fs.readdirSync(keyDirectoryPath)[0])).toString();

    // gRPC client connection
    const client = new grpc.Client(peerEndpoint, tlsCredentials, {
        'grpc.ssl_target_name_override': peerHostAlias,
    });

    // Identity and signer for Fabric Gateway
    const identity = {
        mspId: mspId,
        credentials: Buffer.from(certificate),
    };
    const signer = newSigner(privateKeyPem);

    const gateway = connect({
        client,
        identity,
        signer,
        hash: hash.sha256,
    });

    return { client, gateway, identity };
}

// Helper function to create a new signer using the private key
function newSigner(privateKeyPem) {
    const privateKey = crypto.createPrivateKey(privateKeyPem);
    return signers.newPrivateKeySigner(privateKey);
}

// Function to initialize an incident with input logging
async function initializeIncident(contract) {
    // Define the input parameters
    const responderId = 'MT12345';
    const incidentId = 'INC20231115-001';
    const detectionTime = '2023-11-15T08:45:00Z';
    const incidentType = 'Malware infection';
    const severityLevel = 'High';
    const description = 'Detected unusual network traffic';
    const actionTaken = 'Network isolation initiated';
    const actionTimestamp = '2023-11-15T08:46:00Z';
    const affectedSystems = ['Patient database server', 'ICU monitoring systems'];

    // Log the input parameters
    console.log('\n--- Initializing Incident ---');
    console.log('Input Parameters:');
    console.log(`Responder ID: ${responderId}`);
    console.log(`Incident ID: ${incidentId}`);
    console.log(`Detection Time: ${detectionTime}`);
    console.log(`Incident Type: ${incidentType}`);
    console.log(`Severity Level: ${severityLevel}`);
    console.log(`Description: ${description}`);
    console.log(`Action Taken: ${actionTaken}`);
    console.log(`Action Timestamp: ${actionTimestamp}`);
    console.log(`Affected Systems: ${affectedSystems.join(', ')}`);

    // Submit the transaction
    await contract.submitTransaction(
        'initializeIncident',
        responderId,
        incidentId,
        detectionTime,
        incidentType,
        severityLevel,
        description,
        actionTaken,
        actionTimestamp,
        JSON.stringify(affectedSystems) // Serialize the array if needed
    );
    console.log('*** Incident initialized');
}



// Function to submit evidence, considering both IoT Gateway and Manual submission
async function submitEvidence(contract) {
    // Example data for IoT Gateway submission
    const iotDeviceCollectorId = 'GW001';
    const iotEvidenceId = 'ART20231115-001';
    const iotCollectionTimestamp = '2023-11-15T08:30:00Z';
    const nameAttack = 'Unauthorized Access Attempt';
    const iotEvidenceDetails = 'IoT Gateway Evidence Data';

    // Compute SHA-256 hash for the IoT evidence data
    const iotIntegrityHash = crypto.createHash('sha256').update(iotEvidenceDetails).digest('hex');

    // Upload IoT evidence data to IPFS
    const { path: iotStorageReference } = await ipfs.add(iotEvidenceDetails);
    console.log('*** IoT Data uploaded to IPFS with hash:', iotStorageReference);

    // Log the IoT evidence submission
    console.log('\n--- Submitting Evidence from IoT Gateway ---');
    console.log('Input Parameters for IoT Evidence:');
    console.log(`Device Collector ID: ${iotDeviceCollectorId}`);
    console.log(`Evidence ID: ${iotEvidenceId}`);
    console.log(`Collection Timestamp: ${iotCollectionTimestamp}`);
    console.log(`Name of Attack: ${nameAttack}`);
    console.log(`Integrity Hash: ${iotIntegrityHash}`);
    console.log(`Storage Reference: ${iotStorageReference}`);

    // Submit evidence from IoT Gateway
    await contract.submitTransaction(
        'submitEvidenceFromGateway',
        iotDeviceCollectorId,
        iotEvidenceId,
        iotCollectionTimestamp,
        nameAttack,
        iotIntegrityHash,
        `ipfs://${iotStorageReference}`,
        'CVE-2023-28050', // Vulnerability example
        'High' // Severity Level example
    );
    console.log('*** Evidence from IoT Gateway submitted successfully');

    // Example data for Manual submission
    const manualDeviceCollectorId = 'EC102';
    const incidentId = 'INC20231115-001';
    const manualEvidenceId = 'ART20231115-002';
    const nameEvidence = 'Server Log Files';
    const manualCollectionTimestamp = '2023-11-15T09:45:00Z';
    const artifactType = 'Network logs';
    const toolsUsed = 'LogRipperPro';
    const manualEvidenceDetails = 'Manual Evidence Data for Network Logs';

    // Compute SHA-256 hash for the manual evidence data
    const manualIntegrityHash = crypto.createHash('sha256').update(manualEvidenceDetails).digest('hex');

    // Upload manual evidence data to IPFS
    const { path: manualStorageReference } = await ipfs.add(manualEvidenceDetails);
    console.log('*** Manual Data uploaded to IPFS with hash:', manualStorageReference);

    // Log the Manual evidence submission
    console.log('\n--- Submitting Manual Evidence ---');
    console.log('Input Parameters for Manual Evidence:');
    console.log(`Device Collector ID: ${manualDeviceCollectorId}`);
    console.log(`Incident ID: ${incidentId}`);
    console.log(`Evidence ID: ${manualEvidenceId}`);
    console.log(`Name Evidence: ${nameEvidence}`);
    console.log(`Collection Timestamp: ${manualCollectionTimestamp}`);
    console.log(`Artifact Type: ${artifactType}`);
    console.log(`Tools Used: ${toolsUsed}`);
    console.log(`Integrity Hash: ${manualIntegrityHash}`);
    console.log(`Storage Reference: ${manualStorageReference}`);

    // Submit manual evidence
    await contract.submitTransaction(
        'submitManualEvidence',
        manualDeviceCollectorId,
        incidentId,
        manualEvidenceId,
        nameEvidence,
        manualCollectionTimestamp,
        artifactType,
        toolsUsed,
        manualIntegrityHash,
        `ipfs://${manualStorageReference}`
    );
    console.log('*** Manual evidence submitted successfully');
}

// Function to retrieve and verify evidence
// async function retrieveAndVerifyEvidence(contract, evidenceId, role) {
//     // Log the retrieval request
//     console.log('\n--- Retrieving Evidence ---');
//     console.log(`Role: ${role}`);
//     console.log(`Evidence ID: ${evidenceId}`);

//     try {
//         // Submit the evaluate transaction to retrieve evidence
//         const evidenceBytes = await contract.evaluateTransaction('retrieveEvidence', evidenceId);
        
//         // Decode the byte array to a string
//         const evidenceString = new TextDecoder().decode(evidenceBytes);

//         // Parse the string to JSON
//         const evidence = JSON.parse(evidenceString);

//         // Log the successful retrieval
//         console.log(`*** Evidence ${evidenceId} retrieved successfully`);
//         console.log('Evidence Details:', evidence);

//         return evidence;
//     } catch (error) {
//         // Log any errors encountered during retrieval
//         console.error(`Failed to retrieve evidence ${evidenceId}:`, error.message);
//         throw error;
//     }
// }

// Function to retrieve and verify evidence
async function retrieveAndVerifyEvidence(contract,role) {

    const evidenceId = 'ART20231115-002';
    // Log the retrieval request
    console.log('\n--- Retrieving Evidence ---');
    console.log(`Role: ${role}`);
    console.log(`Evidence ID: ${evidenceId}`);

    try {
        // Submit the evaluate transaction to retrieve evidence
        const evidenceBytes = await contract.evaluateTransaction('retrieveEvidence', evidenceId);
        
        // Decode the byte array to a string
        const evidenceString = new TextDecoder().decode(evidenceBytes);

        // Parse the string to JSON
        const evidence = JSON.parse(evidenceString);

        // Log the successful retrieval
        console.log(`*** Evidence ${evidenceId} retrieved successfully`);
        console.log('Evidence Details:', evidence);

        // Retrieve the data from IPFS using the storageReference
        const ipfsHash = evidence.storageReference.split('ipfs://')[1]; // Extract IPFS hash
        console.log(`Fetching data from IPFS with hash: ${ipfsHash}`);

        const ipfsDataString = await getDataFromIPFS(ipfs,ipfsHash)

        console.log('Added file contents from IPFS:', ipfsDataString);

        const hash = crypto.createHash('sha256').update(ipfsDataString).digest('hex');

        // Compare the computed hash with the stored integrity hash
        if (hash === evidence.integrityHash) {
            console.log('*** Data hashed matches with the hash from Blockchain');
            console.log('*** Data integrity verified successfully');
        } else {
            console.error('*** Data integrity verification failed');
            throw new Error('Data integrity verification failed. The hashes do not match.');
        }

        return evidence;
    } catch (error) {
        // Log any errors encountered during retrieval
        console.error(`Failed to retrieve evidence ${evidenceId}:`, error.message);
        throw error;
    }
}

// Function to create a forensic report and interact with the blockchain
async function createForensicReport(contract) {
    console.log('\n--- Creating Forensic Report ---');

    // Sample data for the forensic report
    const investigatorId = 'INV12345';
    const incidentId = 'INC20231115-001';
    const reportId = 'REP20231115-001';
    const reportTimestamp = new Date().toISOString();
    const analysis = 'Malware Analysis: The malware exploited a vulnerability in the network.';
    const findings = 'The malware infection spread to critical healthcare devices, impacting patient safety.';

    // Log the input parameters
    console.log('Input Parameters:');
    console.log(`Investigator ID: ${investigatorId}`);
    console.log(`Incident ID: ${incidentId}`);
    console.log(`Report ID: ${reportId}`);
    console.log(`Report Timestamp: ${reportTimestamp}`);
    console.log(`Analysis: ${analysis}`);
    console.log(`Findings: ${findings}`);

    // Upload the analysis and findings to IPFS
    const ipfsData = `${analysis}\n${findings}`;
    const { cid } = await ipfs.add(ipfsData);
    const storageReference = `ipfs://${cid}`;

    console.log(`*** Report data uploaded to IPFS with CID: ${cid}`);

    try {
        // Submit the transaction to create the forensic report
        await contract.submitTransaction(
            'createForensicReport',
            investigatorId,
            incidentId,
            reportId,
            reportTimestamp,
            analysis,
            findings,
            storageReference
        );

        console.log(`*** Forensic report ${reportId} created successfully`);
    } catch (error) {
        console.error(`Failed to create forensic report ${reportId}:`, error.message);
        throw error;
    }
}




main();

// Helper function to retrieve and decode data from IPFS
async function getDataFromIPFS(ipfs, ipfsHash) {
    const decoder = new TextDecoder();
    let dataString = '';

    for await (const chunk of ipfs.cat(ipfsHash)) {
        dataString += decoder.decode(chunk, { stream: true });
    }

    return dataString;
}
