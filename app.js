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

         // Update chain of custody for evidence
         console.log('\n--- Updating Chain of Custody Entries ---');
         await updateChainOfCustody(evidenceContract, 'ART20231115-002', 'Collected', 'EvidenceCollector104', 'Storage Facility', 'Sealed');
         await updateChainOfCustody(evidenceContract, 'ART20231115-002', 'Transferred', 'EvidenceTrasferror105', 'Lab', 'Opened for Analysis');

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

        // Retrieve and display chain of custody
        console.log('\n--- Using Forensic Investigator Credentials ---');
        console.log('\n--- Retrieving Chain of Custody ---');
        await getChainOfCustody(forensicContract, 'ART20231115-002');

        console.log('\n=== CHAIN OF CUSTODY TESTING COMPLETED ===');

        // Use Forensic Investigator credentials to retrieve the forensic report
        console.log('\n--- Using Forensic Investigator Credentials ---');
        await retrieveForensicReport(forensicContract, 'REP20231115-001', 'Forensic Investigator');


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
    const manualDeviceCollectorId = 'EvidenceCollector103';
    const incidentId = 'INC20231115-001';
    const manualEvidenceId = 'ART20231115-002';
    const nameEvidence = 'Server Log Files';
    const manualCollectionTimestamp = '2023-11-15T09:45:00Z';
    const artifactType = 'Network logs';
    const toolsUsed = 'LogRipperPro';

    const videoPath = './Crop_fit.mp4'; // Path to your video file

    // Read the video file
    const videoFile = fs.readFileSync(videoPath);

    // Compute SHA-256 hash for the manual evidence data
    const manualIntegrityHash = crypto.createHash('sha256').update(videoFile).digest('hex');

    // Upload manual evidence data to IPFS
    const { path: videoStorageReference } = await ipfs.add(videoFile);
    console.log('*** Video uploaded to IPFS with hash:', videoStorageReference);

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
    console.log(`Storage Reference: ${videoStorageReference}`);

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
        `ipfs://${videoStorageReference}`
    );
    console.log('*** Manual evidence submitted successfully');
}


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

        // const ipfsDataString = await getDataFromIPFS(ipfs,ipfsHash)

        // console.log('Added file contents from IPFS:', ipfsDataString);

        const ipfsVideoBuffer = await getVideoFromIPFS(ipfs, ipfsHash);

        // Save the retrieved video locally (optional)
        const outputPath = './retrieved_video.mp4';
        fs.writeFileSync(outputPath, ipfsVideoBuffer);
        console.log('Retrieved video saved locally as:', outputPath);

        const hash = crypto.createHash('sha256').update(ipfsVideoBuffer).digest('hex');

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
    const pdfPath = './Forensic Examination Report.pdf'; // Path to your PDF file


    // Log the input parameters
    console.log('Input Parameters:');
    console.log(`Investigator ID: ${investigatorId}`);
    console.log(`Incident ID: ${incidentId}`);
    console.log(`Report ID: ${reportId}`);
    console.log(`Report Timestamp: ${reportTimestamp}`);
    // console.log(`Analysis: ${analysis}`);
    // console.log(`Findings: ${findings}`);
    console.log(`PDF Path: ${pdfPath}`);

    // Read the PDF file
    const pdfFile = fs.readFileSync(pdfPath);

    // Upload the PDF file to IPFS
    const { path: pdfStorageReference } = await ipfs.add(pdfFile);
    console.log('*** PDF uploaded to IPFS with hash:', pdfStorageReference);

    // Upload the analysis and findings to IPFS
    // const ipfsData = `${analysis}\n${findings}`;
    // const { cid } = await ipfs.add(ipfsData);
    // const storageReference = `ipfs://${cid}`;

    const storageReference = `ipfs://${pdfStorageReference}`;

    // console.log(`*** Report data uploaded to IPFS with CID: ${pdfStorageReference}`);

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


// Function to update the chain of custody with detailed logging
async function updateChainOfCustody(contract, evidenceId, action, userId, location, condition) {
    console.log(`\n--- Updating Chain of Custody ---`);
    console.log(`Input Parameters:`);
    console.log(`  Evidence ID: ${evidenceId}`);
    console.log(`  Action: ${action}`);
    console.log(`  User ID: ${userId}`);
    console.log(`  Location: ${location}`);
    console.log(`  Condition: ${condition}`);

    // Add a timestamp for the action
    const actionTimestamp = new Date().toISOString();
    console.log(`  Timestamp: ${actionTimestamp}`);

    try {
        // Submit the transaction with the correct number of parameters
        await contract.submitTransaction(
            'updateChainOfCustody',
            evidenceId,
            action,
            userId,
            location,
            condition,
            actionTimestamp // Add this parameter
        );
        console.log(`*** Chain of custody updated successfully for Evidence ID: ${evidenceId}`);
        console.log(`  Action Taken: ${action}`);
        console.log(`  Performed By: ${userId}`);
        console.log(`  Location: ${location}`);
        console.log(`  Condition: ${condition}`);
        console.log(`  Timestamp: ${actionTimestamp}`);
    } catch (error) {
        console.error(`Failed to update chain of custody for Evidence ID ${evidenceId}:`, error.message);
        throw error;
    }
}


// Function to retrieve and display the chain of custody with detailed logging
async function getChainOfCustody(contract, evidenceId) {
    console.log(`\n--- Retrieving Chain of Custody ---`);
    console.log(`Querying for Evidence ID: ${evidenceId}`);

    try {
        // Evaluate the transaction
        const chainOfCustodyBytes = await contract.evaluateTransaction('getChainOfCustody', evidenceId);
        const chainOfCustody = JSON.parse(new TextDecoder().decode(chainOfCustodyBytes));

        console.log(`\n*** Chain of Custody Records for Evidence ID: ${evidenceId} ***`);
        chainOfCustody.forEach((entry, index) => {
            console.log(`Entry ${index + 1}:`);
            console.log(`  Action: ${entry.action}`);
            console.log(`  Performed By: ${entry.actor}`);
            console.log(`  Location: ${entry.location}`);
            console.log(`  Condition: ${entry.condition}`);
            console.log(`  Timestamp: ${entry.timestamp}`);
        });

        return chainOfCustody;
    } catch (error) {
        console.error(`Failed to retrieve chain of custody for Evidence ID ${evidenceId}:`, error.message);
        throw error;
    }
}

async function retrieveForensicReport(contract, reportId, role) {
    console.log(`\n--- Retrieving Forensic Report ---`);
    console.log(`Role: ${role}`);
    console.log(`Report ID: ${reportId}`);

    try {
        // Evaluate the transaction to retrieve the forensic report
        const reportBytes = await contract.evaluateTransaction('retrieveForensicReport', reportId);

        // Decode the byte array to a string
        const reportString = utf8Decoder.decode(reportBytes);

        // Parse the string to JSON
        const report = JSON.parse(reportString);

        console.log(`*** Forensic report ${reportId} retrieved successfully`);
        console.log('Report Details:', report);

        // Retrieve the PDF from IPFS using the storageReference
        const ipfsHash = report.storageReference.split('ipfs://')[1]; // Extract IPFS hash
        console.log(`Fetching PDF from IPFS with hash: ${ipfsHash}`);

        const pdfBuffer = await getVideoFromIPFS(ipfs, ipfsHash); // Reusing `getVideoFromIPFS` for binary data

        // Save the retrieved PDF locally (optional)
        const outputPath = './retrieved_report.pdf';
        fs.writeFileSync(outputPath, pdfBuffer);
        console.log('Retrieved forensic report PDF saved locally as:', outputPath);

        return report;
    } catch (error) {
        console.error(`Failed to retrieve forensic report ${reportId}:`, error.message);
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

async function getVideoFromIPFS(ipfs, ipfsHash) {
    const chunks = [];

    for await (const chunk of ipfs.cat(ipfsHash)) {
        chunks.push(chunk);
    }

    return Buffer.concat(chunks); // Combine chunks into a single buffer
}
