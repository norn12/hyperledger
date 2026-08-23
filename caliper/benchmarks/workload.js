'use strict';

const { WorkloadModuleBase } = require('@hyperledger/caliper-core');
const crypto = require('crypto');

class MyWorkload extends WorkloadModuleBase {
    constructor() {
        super();
        this.txIndex = 0;
    }

    async initializeWorkloadModule(workerIndex, totalWorkers, numberofRequests, caliperContext, blockchainConfig) {
        await super.initializeWorkloadModule(workerIndex, totalWorkers, numberofRequests, caliperContext, blockchainConfig);
    }

    async submitTransaction() {
        this.txIndex++;
        const rawPatientID = `PATIENT_${this.workerIndex}_${this.txIndex}`;
        const patientIDHash = crypto.createHash('sha256').update(rawPatientID).digest('hex');
        
        const recordID = `rec-${patientIDHash.substring(0, 8)}-${Date.now()}-${this.txIndex}`;
        const dataHash = crypto.createHash('sha256').update(`DATA_PAYLOAD_${this.txIndex}_${Date.now()}`).digest('hex');
        const zkpProofHash = crypto.createHash('sha256').update(`ZKP_PROOF_AGE_${this.txIndex}_${Date.now()}`).digest('hex');

        const accessPolicy = JSON.stringify({
            requireZKP: true,
            allowedMSPs: ['HospitalMSP', 'InsurerMSP']
        });

        const request = {
            contractId: 'health',
            contractFunction: 'CreateHealthRecord',
            invokerMspId: 'HospitalMSP',
            contractArguments: [
                recordID, 
                patientIDHash, 
                dataHash, 
                'ipfs://caliper-bench', 
                zkpProofHash, 
                'CLINICAL_BENCHMARK', 
                accessPolicy
            ],
            readOnly: false
        };

        try {
            await this.sutAdapter.sendRequests(request);
        } catch (err) {
            console.error(`[Caliper] Transaction failed: ${err.message}`);
        }
    }

    async cleanupWorkloadModule() {
        // Cleanup complete
    }
}

function createWorkloadModule() {
    return new MyWorkload();
}

module.exports.createWorkloadModule = createWorkloadModule;
