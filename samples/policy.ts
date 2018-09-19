import * as common from './common';
import * as nodeApi from 'azure-devops-node-api';

import * as PolicyApi from 'azure-devops-node-api/PolicyApi';
import * as PolicyInterfaces from 'azure-devops-node-api/interfaces/PolicyInterfaces';
import * as VSSInterfaces from 'azure-devops-node-api/interfaces/common/VSSInterfaces';

export async function run() {
    let webApi: nodeApi.WebApi = await common.getWebApi();
    let policyApiObject: PolicyApi.IPolicyApi = await webApi.getPolicyApi();

    common.banner('Policy Samples');
    let project: string = common.getProject();
    console.log('Project:', project);

    common.heading("Get Policy Configurations for this Project");
    const configurations: PolicyInterfaces.PolicyConfiguration[] = await policyApiObject.getPolicyConfigurations(project);
    if (configurations.length > 0){
        const firstConfig = configurations[0];
        const creatorIdentity = firstConfig.createdBy;
        console.log("Sample configuration created by", creatorIdentity.displayName);

        common.heading("Get revisions for this configuration");
        const revisions: PolicyInterfaces.PolicyConfiguration[] = await policyApiObject.getPolicyConfigurationRevisions(project, firstConfig.id);
        if (revisions.length > 0) {
            console.log("Sample revision:", revisions[0]);
        }
        else {
            console.log("No revisions for this policy")
        }
    }
    else {
        console.log("No configurations for this project");
    }

    common.heading("Get Policy Types for this Project");
    const policies: PolicyInterfaces.PolicyType[] = await policyApiObject.getPolicyTypes(project);
    if (policies.length > 0){
        console.log("Sample type:", policies[0]);
    }
    else {
        console.log("No policy types for this project");
    }
}