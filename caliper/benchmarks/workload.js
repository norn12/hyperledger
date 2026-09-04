'use strict';

const { WorkloadModuleBase } = require('@hyperledger/caliper-core');
const crypto = require('crypto');

class FabricBaselineWorkload extends WorkloadModuleBase {
    constructor() {
        super();
        this.txIndex = 0;
    }

    async initializeWorkloadModule(workerIndex, totalWorkers, numberofRequests, caliperContext, blockchainConfig) {
        await super.initializeWorkloadModule(workerIndex, totalWorkers, numberofRequests, caliperContext, blockchainConfig);
    }

    async submitTransaction() {
        this.txIndex++;
        const rawPatientID = `CALIPER_BASELINE_${this.workerIndex}_${this.txIndex}`;
        const patientIDHash = crypto.createHash('sha256').update(rawPatientID).digest('hex');
        const payload = `BASELINE_DATA_${this.workerIndex}_${this.txIndex}`;
        const dataHash = crypto.createHash('sha256').update(payload).digest('hex');
        const recordID = `cal-${this.workerIndex}-${this.txIndex}-${Date.now()}`;

        // Baseline deliberately contains no Groth16 proof generation.
        // CreateHealthRecord stores the empty proof field; this isolates
        // Fabric endorsement/order/validation/commit performance.
        const accessPolicy = JSON.stringify({
            requireZKP: false,
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
                'offchain://caliper-baseline',
                '',
                'CALIPER_BASELINE',
                accessPolicy
            ],
            readOnly: false
        };

        await this.sutAdapter.sendRequests(request);
    }

    async cleanupWorkloadModule() {}
}

function createWorkloadModule() {
    return new FabricBaselineWorkload();
}

module.exports.createWorkloadModule = createWorkloadModule;
