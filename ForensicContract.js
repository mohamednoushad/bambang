'use strict';

const { Contract } = require('fabric-contract-api');

class ForensicContract extends Contract {
    // Access control helper with ABAC
    _checkAccess(ctx, requiredAttributes) {
        const identity = ctx.clientIdentity;
        const userRole = identity.getAttributeValue('role');
        const clearanceLevel = identity.getAttributeValue('clearance');

        if (!requiredAttributes.roles.includes(userRole) || !requiredAttributes.clearance.includes(clearanceLevel)) {
            throw new Error(`Access denied: User with role ${userRole} and clearance level ${clearanceLevel} is not authorized to perform this action.`);
        }
    }

    // Log actions for auditing
    async logAction(ctx, action, userId, role) {
        const txTimestamp = ctx.stub.getTxTimestamp();
        const actionTimestamp = new Date(txTimestamp.seconds * 1000).toISOString();
        const logEntry = { action, userId, role, actionTimestamp };

        await ctx.stub.putState(`log_${actionTimestamp}`, Buffer.from(JSON.stringify(logEntry)));
        console.log(`Action ${action} by ${userId} with role ${role} logged at ${actionTimestamp}.`);
    }

    // Initialize Incident Record
    async initializeIncident(ctx, responderId, incidentId, detectionTime, incidentType, severityLevel, description, actionTaken, actionTimestamp, affectedSystems) {
        this._checkAccess(ctx, { roles: ['Monitoring Team'], clearance: ['Low'] });

        const incidentRecord = {
            responderId,
            incidentId,
            detectionTime,
            incidentType,
            severityLevel,
            description,
            initialActions: [{ actionTaken, actionTimestamp }],
            affectedSystems,
            status: 'initialized',
            evidenceList: []
        };

        await ctx.stub.putState(incidentId, Buffer.from(JSON.stringify(incidentRecord)));
        console.log(`Incident ${incidentId} initialized by ${responderId}.`);

        // Log the action
        await this.logAction(ctx, 'initializeIncident', responderId, 'Monitoring Team');
    }

    // Submit Evidence by IoT Gateway
    async submitEvidenceFromGateway(ctx, deviceCollectorId, evidenceId, collectionTimestamp, nameAttack, integrityHash, storageReference, vulnerability, severityLevel) {
        this._checkAccess(ctx, { roles: ['Evidence Collector'], clearance: ['Medium'] });

        const evidence = {
            deviceCollectorId,
            evidenceId,
            collectionTimestamp,
            nameAttack,
            integrityHash,
            storageReference,
            vulnerability,
            severityLevel,
            status: 'submitted'
        };

        await ctx.stub.putState(evidenceId, Buffer.from(JSON.stringify(evidence)));
        console.log(`Evidence ${evidenceId} submitted from IoT Gateway ${deviceCollectorId}.`);

        // Log the action
        await this.logAction(ctx, 'submitEvidenceFromGateway', deviceCollectorId, 'Evidence Collector');
    }

    // Submit Evidence Manually
    async submitManualEvidence(ctx, deviceCollectorId, incidentId, evidenceId, nameEvidence, collectionTimestamp, artifactType, toolsUsed, integrityHash, storageReference) {
        this._checkAccess(ctx, { roles: ['Evidence Collector'], clearance: ['Medium'] });

        const evidence = {
            deviceCollectorId,
            incidentId,
            evidenceId,
            nameEvidence,
            collectionTimestamp,
            artifactType,
            toolsUsed,
            integrityHash,
            storageReference,
            status: 'submitted'
        };

        await ctx.stub.putState(evidenceId, Buffer.from(JSON.stringify(evidence)));
        console.log(`Manual evidence ${evidenceId} submitted by ${deviceCollectorId}.`);

        // Link evidence to the incident
        const incidentBytes = await ctx.stub.getState(incidentId);
        if (!incidentBytes || incidentBytes.length === 0) {
            throw new Error(`Incident ${incidentId} does not exist.`);
        }
        const incident = JSON.parse(incidentBytes.toString());
        incident.evidenceList.push(evidenceId);
        await ctx.stub.putState(incidentId, Buffer.from(JSON.stringify(incident)));

        // Log the action
        await this.logAction(ctx, 'submitManualEvidence', deviceCollectorId, 'Evidence Collector');
    }

    // Retrieve and Verify Evidence
    async retrieveEvidence(ctx, evidenceId) {
        this._checkAccess(ctx, { roles: ['Forensic Investigator', 'Judge'], clearance: ['High', 'Judicial'] });

        const evidenceBytes = await ctx.stub.getState(evidenceId);
        if (!evidenceBytes || evidenceBytes.length === 0) {
            throw new Error(`Evidence ${evidenceId} does not exist.`);
        }

        const evidence = JSON.parse(evidenceBytes.toString());
        console.log(`Evidence ${evidenceId} retrieved successfully.`);

        // Log the action
        await this.logAction(ctx, 'retrieveEvidence', ctx.clientIdentity.getID(), 'Forensic Investigator or Judge');

        return JSON.stringify(evidence);
    }

    // Create Forensic Report
    async createForensicReport(ctx, investigatorId, incidentId, reportId, reportTimestamp, analysis, findings, storageReference) {
        this._checkAccess(ctx, { roles: ['Forensic Investigator'], clearance: ['High'] });

        const forensicReport = {
            investigatorId,
            incidentId,
            reportId,
            reportTimestamp,
            analysis,
            findings,
            storageReference,
            status: 'created'
        };

        await ctx.stub.putState(reportId, Buffer.from(JSON.stringify(forensicReport)));
        console.log(`Forensic report ${reportId} created by ${investigatorId}.`);

        // Update the incident status
        const incidentBytes = await ctx.stub.getState(incidentId);
        if (!incidentBytes || incidentBytes.length === 0) {
            throw new Error(`Incident ${incidentId} does not exist.`);
        }
        const incident = JSON.parse(incidentBytes.toString());
        incident.status = 'report created';
        await ctx.stub.putState(incidentId, Buffer.from(JSON.stringify(incident)));

        // Log the action
        await this.logAction(ctx, 'createForensicReport', investigatorId, 'Forensic Investigator');
    }
}

module.exports = ForensicContract;