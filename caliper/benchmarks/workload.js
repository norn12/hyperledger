'use strict';

const { WorkloadModuleBase } = require('@hyperledger/caliper-core');

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
        const recordID = `bench-caliper-${this.workerIndex}-${this.txIndex}-${Date.now()}`;
        const patientID = `PATIENT_${this.workerIndex}_${this.txIndex}`;
        const dataHash = `DATA_HASH_${Date.now()}`;
        const zkpProofHash = `ZKP_HASH_${Date.now()}`;

        const request = {
            contractId: 'health',
            contractFunction: 'CreateHealthRecord',
            invokerMspId: 'HospitalMSP',
            contractArguments: [
                recordID, 
                patientID, 
                dataHash, 
                'ipfs://caliper-bench', 
                zkpProofHash, 
                'CLINICAL_TEST', 
                '{"requireZKP": true}'
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
        // No cleanup needed for now
    }
}

function createWorkloadModule() {
    return new MyWorkload();
}

module.exports.createWorkloadModule = createWorkloadModule;
