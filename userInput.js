const { connect, Identity, Signer, hash, signers } = require('@hyperledger/fabric-gateway');
const grpc = require('@grpc/grpc-js');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { TextDecoder } = require('util');
const readline = require('readline');


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

// Create a readline interface for user interaction
const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
});

// Helper function to ask questions and handle default values
async function askQuestion(question, defaultValue) {
    return new Promise((resolve) => {
        rl.question(`${question} [Default: ${defaultValue}]: `, (input) => {
            resolve(input || defaultValue);
        });
    });
}

// Modified main function to log roles when initializing and using contracts
async function main() {
    try {

        // Dynamically import IPFS and create an instance
        const { create } = await import('ipfs-core');
        ipfs = await create({ repo: 'ok' + Math.random() });

        console.log('\n--- Interactive Incident Management System ---\n');

          // Get input for initializing an incident
          const responderId = await askQuestion('Enter Responder ID', 'MT12345');
          const incidentId = await askQuestion('Enter Incident ID', 'INC20231115-001');
          const detectionTime = await askQuestion('Enter Detection Time (ISO format)', '2023-11-15T08:45:00Z');
          const incidentType = await askQuestion('Enter Incident Type', 'Malware infection');
          const severityLevel = await askQuestion('Enter Severity Level', 'High');
          const description = await askQuestion('Enter Incident Description', 'Detected unusual network traffic');
          const actionTaken = await askQuestion('Enter Initial Action Taken', 'Network isolation initiated');
          const actionTimestamp = await askQuestion('Enter Action Timestamp (ISO format)', '2023-11-15T08:46:00Z');
          const affectedSystems = await askQuestion(
              'Enter Affected Systems (comma-separated)',
              'Patient database server,ICU monitoring systems'
          );

          console.log('\n--- Using Monitoring Team Credentials ---');
        const monitoringContract = await createContract(monitoringCertPath, monitoringKeyDirectoryPath, 'Monitoring Team');
        await initializeIncident(monitoringContract, {
            responderId,
            incidentId,
            detectionTime,
            incidentType,
            severityLevel,
            description,
            actionTaken,
            actionTimestamp,
            affectedSystems: affectedSystems.split(','),
        });

          // Example Evidence Submission
          console.log('\n--- Using Evidence Collector Credentials ---');
          const evidenceContract = await createContract(evidenceCollectorCertPath, evidenceCollectorKeyDirectoryPath, 'Evidence Collector');
          const manualEvidenceId = await askQuestion('Enter Manual Evidence ID', 'ART20231115-002');
          const artifactType = await askQuestion('Enter Artifact Type', 'Network logs');
          const toolsUsed = await askQuestion('Enter Tools Used', 'LogRipperPro');
          const collectionTimestamp = await askQuestion('Enter Collection Timestamp', '2023-11-15T09:45:00Z');
          const nameEvidence = await askQuestion('Enter Name of Evidence', 'Server Log Files');
          const manualEvidenceDetails = await askQuestion('Enter Evidence Details', 'Manual Evidence Data for Network Logs');
  
          await submitEvidence(evidenceContract, {
              manualEvidenceId,
              artifactType,
              toolsUsed,
              collectionTimestamp,
              nameEvidence,
              manualEvidenceDetails,
          });

          await updateChainOfCustody(evidenceContract);

        // Use Forensic Investigator credentials
        const forensicContract = await createContract(forensicCertPath, forensicKeyDirectoryPath, 'Forensic Investigator');
        await retrieveAndVerifyEvidence(forensicContract, 'Forensic Investigator');
        await createForensicReport(forensicContract);

        // Retrieve Chain of Custody
        console.log('\n--- Using Forensic Investigator Credentials ---');
        await getChainOfCustody(forensicContract);


  
          // Close readline interface after all interactions
          rl.close();
  
          console.log('\n=== TESTING COMPLETED ===');
          
      } catch (error) {
          console.error('Error:', error.message);
          rl.close();
          process.exit(1);


        // // Use Evidence Collector credentials for submitting evidence and log role
        // console.log('\n--- Using Evidence Collector Credentials ---');
        // const evidenceContract = await createContract(evidenceCollectorCertPath, evidenceCollectorKeyDirectoryPath, 'Evidence Collector');
        // await submitEvidence(evidenceContract);

        //  // Update chain of custody for evidence
        //  console.log('\n--- Updating Chain of Custody Entries ---');
        //  await updateChainOfCustody(evidenceContract, 'ART20231115-002', 'Collected', 'EvidenceCollector104', 'Storage Facility', 'Sealed');
        //  await updateChainOfCustody(evidenceContract, 'ART20231115-002', 'Transferred', 'EvidenceTransferror105', 'Lab', 'Opened for Analysis');

        // // Use Forensic Investigator credentials for retrieving evidence
        // console.log('\n--- Using Forensic Investigator Credentials ---');
        // const forensicContract = await createContract(forensicCertPath, forensicKeyDirectoryPath, 'Forensic Investigator');
        // await retrieveAndVerifyEvidence(forensicContract, 'Forensic Investigator');

        // // Use Judge credentials for retrieving evidence
        // console.log('\n--- Using Judge Credentials ---');
        // const judgeContract = await createContract(judgeCertPath, judgeKeyDirectoryPath, 'Judge');
        // await retrieveAndVerifyEvidence(judgeContract, 'Judge');

        //  // Call the function to create a forensic report
        //  await createForensicReport(forensicContract);

        // // Retrieve and display chain of custody
        // console.log('\n--- Using Forensic Investigator Credentials ---');
        // console.log('\n--- Retrieving Chain of Custody ---');
        // await getChainOfCustody(forensicContract, 'ART20231115-002');

        // console.log('\n=== CHAIN OF CUSTODY TESTING COMPLETED ===');


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

// Function to initialize an incident
async function initializeIncident(contract, data) {
    console.log('\n--- Initializing Incident ---');
    console.log('Data:', data);

    await contract.submitTransaction(
        'initializeIncident',
        data.responderId,
        data.incidentId,
        data.detectionTime,
        data.incidentType,
        data.severityLevel,
        data.description,
        data.actionTaken,
        data.actionTimestamp,
        JSON.stringify(data.affectedSystems)
    );
    console.log('*** Incident initialized');
}

// Function to submit evidence
async function submitEvidence(contract, data) {
    console.log('\n--- Submitting Evidence ---');
    console.log('Data:', data);

    const integrityHash = crypto.createHash('sha256').update(data.manualEvidenceDetails).digest('hex');
    const { path: storageReference } = await ipfs.add(data.manualEvidenceDetails);

    await contract.submitTransaction(
        'submitManualEvidence',
        'EC102', // Device Collector ID (can also be dynamic)
        'INC20231115-001', // Link to incident ID
        data.manualEvidenceId,
        data.nameEvidence,
        data.collectionTimestamp,
        data.artifactType,
        data.toolsUsed,
        integrityHash,
        `ipfs://${storageReference}`
    );

    console.log('*** Manual evidence submitted successfully');
}

async function retrieveAndVerifyEvidence(contract, role) {
    const evidenceId = await askQuestion('Enter Evidence ID to retrieve', 'ART20231115-002');
    console.log(`\n--- Retrieving Evidence ---`);
    console.log(`Role: ${role}`);
    console.log(`Evidence ID: ${evidenceId}`);

    try {
        // Submit the evaluate transaction to retrieve evidence
        const evidenceBytes = await contract.evaluateTransaction('retrieveEvidence', evidenceId);
        const evidenceString = new TextDecoder().decode(evidenceBytes);
        const evidence = JSON.parse(evidenceString);

        console.log(`*** Evidence ${evidenceId} retrieved successfully`);
        console.log('Evidence Details:', evidence);

        // Retrieve the data from IPFS using the storageReference
        const ipfsHash = evidence.storageReference.split('ipfs://')[1];
        console.log(`Fetching data from IPFS with hash: ${ipfsHash}`);

        const ipfsDataString = await getDataFromIPFS(ipfs, ipfsHash);

        console.log('IPFS Data:', ipfsDataString);

        const hash = crypto.createHash('sha256').update(ipfsDataString).digest('hex');
        if (hash === evidence.integrityHash) {
            console.log('*** Data integrity verified successfully');
        } else {
            console.error('*** Data integrity verification failed');
            throw new Error('The hashes do not match.');
        }
    } catch (error) {
        console.error(`Failed to retrieve evidence ${evidenceId}:`, error.message);
    }
}

async function createForensicReport(contract) {
    console.log('\n--- Creating Forensic Report ---');

    const investigatorId = await askQuestion('Enter Investigator ID', 'INV12345');
    const incidentId = await askQuestion('Enter Incident ID', 'INC20231115-001');
    const reportId = await askQuestion('Enter Report ID', 'REP20231115-001');
    const reportTimestamp = new Date().toISOString(); // Auto-generated timestamp
    const analysis = await askQuestion('Enter Analysis', 'Malware Analysis: The malware exploited a vulnerability in the network.');
    const findings = await askQuestion('Enter Findings', 'The malware infection spread to critical healthcare devices, impacting patient safety.');

    // Upload report data to IPFS
    const ipfsData = `${analysis}\n${findings}`;
    const { cid } = await ipfs.add(ipfsData);
    const storageReference = `ipfs://${cid}`;
    console.log(`*** Report data uploaded to IPFS with CID: ${cid}`);

    try {
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
    }
}

async function updateChainOfCustody(contract) {
    console.log('\n--- Updating Chain of Custody ---');

    const evidenceId = await askQuestion('Enter Evidence ID', 'ART20231115-002');
    const action = await askQuestion('Enter Action', 'Transferred');
    const userId = await askQuestion('Enter User ID', 'EvidenceTransferror105');
    const location = await askQuestion('Enter Location', 'Lab');
    const condition = await askQuestion('Enter Condition', 'Opened for Analysis');
    const actionTimestamp = new Date().toISOString(); // Auto-generated timestamp

    try {
        await contract.submitTransaction(
            'updateChainOfCustody',
            evidenceId,
            action,
            userId,
            location,
            condition,
            actionTimestamp
        );
        console.log(`*** Chain of custody updated successfully for Evidence ID: ${evidenceId}`);
    } catch (error) {
        console.error(`Failed to update chain of custody for Evidence ID ${evidenceId}:`, error.message);
    }
}

async function getChainOfCustody(contract) {
    console.log('\n--- Retrieving Chain of Custody ---');

    const evidenceId = await askQuestion('Enter Evidence ID to retrieve Chain of Custody', 'ART20231115-002');

    try {
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
    } catch (error) {
        console.error(`Failed to retrieve chain of custody for Evidence ID ${evidenceId}:`, error.message);
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
