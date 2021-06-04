// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

import VsoBaseInterfaces = require('./interfaces/common/VsoBaseInterfaces');
import basem = require('./ClientApiBases');
import buildm = require('./BuildApi');
import corem = require('./CoreApi');
import dashboardm = require('./DashboardApi');
import extmgmtm = require("./ExtensionManagementApi");
import featuremgmtm = require("./FeatureManagementApi");
import filecontainerm = require('./FileContainerApi');
import gallerym = require('./GalleryApi');
import gitm = require('./GitApi');
import locationsm = require('./LocationsApi');
import notificationm = require('./NotificationApi');
import policym = require('./PolicyApi');
import profilem = require('./ProfileApi');
import projectm = require('./ProjectAnalysisApi');
import releasem = require('./ReleaseApi');
import securityrolesm = require('./SecurityRolesApi');
import taskagentm = require('./TaskAgentApi');
import taskm = require('./TaskApi');
import testm = require('./TestApi');
import tfvcm = require('./TfvcApi');
import wikim = require('./WikiApi');
import workm = require('./WorkApi');
import workitemtrackingm = require('./WorkItemTrackingApi');
import workitemtrackingprocessm = require('./WorkItemTrackingProcessApi');
import workitemtrackingprocessdefinitionm = require('./WorkItemTrackingProcessDefinitionsApi');
import basicm = require('./handlers/basiccreds');
import bearm = require('./handlers/bearertoken');
import ntlmm = require('./handlers/ntlm');
import patm = require('./handlers/personalaccesstoken');

import * as rm from 'typed-rest-client/RestClient';
import vsom = require('./VsoClient');
import lim = require("./interfaces/LocationsInterfaces");

import crypto = require('crypto');
import fs = require('fs');
import os = require('os');
import url = require('url');
import path = require('path');

// https://www.electronjs.org/docs/api/process
interface ElectronProcess {
  type: 'browser' | 'renderer' | 'worker'
};
const isElectron: boolean = process && process.versions && process.versions.hasOwnProperty('electron');
const isElectronWebpage: boolean = isElectron && (<ElectronProcess><unknown>process).type === 'renderer';
const isBrowser: boolean = typeof window !== 'undefined' && (!isElectron || isElectronWebpage);

/**
 * Methods to return handler objects (see handlers folder)
 */

export function getBasicHandler(username: string, password: string, allowCrossOriginAuthentication?: boolean): VsoBaseInterfaces.IRequestHandler {
    return new basicm.BasicCredentialHandler(username, password, allowCrossOriginAuthentication);
}

export function getNtlmHandler(username: string, password: string, workstation?: string, domain?: string): VsoBaseInterfaces.IRequestHandler {
    return new ntlmm.NtlmCredentialHandler(username, password, workstation, domain);
}

export function getBearerHandler(token: string, allowCrossOriginAuthentication?: boolean): VsoBaseInterfaces.IRequestHandler {
    return new bearm.BearerCredentialHandler(token, allowCrossOriginAuthentication);
}

export function getPersonalAccessTokenHandler(token: string, allowCrossOriginAuthentication?: boolean): VsoBaseInterfaces.IRequestHandler {
    return new patm.PersonalAccessTokenCredentialHandler(token, allowCrossOriginAuthentication);
}

export function getHandlerFromToken(token: string, allowCrossOriginAuthentication?: boolean): VsoBaseInterfaces.IRequestHandler {
    if (token.length === 52) {
        return getPersonalAccessTokenHandler(token, allowCrossOriginAuthentication);
    }
    else {
        return getBearerHandler(token, allowCrossOriginAuthentication);
    }
}

export interface IWebApiRequestSettings {
    productName: string,
    productVersion: string
};

// ---------------------------------------------------------------------------
// Factory to return client apis
// When new APIs are added, a method must be added here to instantiate the API
//----------------------------------------------------------------------------
export class WebApi {

    public serverUrl: string;
    public authHandler: VsoBaseInterfaces.IRequestHandler;
    public rest: rm.RestClient;
    public vsoClient: vsom.VsoClient;
    public options: VsoBaseInterfaces.IRequestOptions;

    private _resourceAreas: lim.ResourceAreaInfo[];

    /*
     * Factory to return client apis and handlers
     * @param defaultUrl default server url to use when creating new apis from factory methods
     * @param authHandler default authentication credentials to use when creating new apis from factory methods
     */
    constructor(defaultUrl: string, authHandler: VsoBaseInterfaces.IRequestHandler, options?: VsoBaseInterfaces.IRequestOptions, requestSettings?: IWebApiRequestSettings) {
        this.serverUrl = defaultUrl;
        this.authHandler = authHandler;
        this.options = options || {};

        if (!this.isNoProxyHost(this.serverUrl)) {
            // try to get proxy setting from environment variable set by VSTS-Task-Lib if there is no proxy setting in the options
            if (!this.options.proxy || !this.options.proxy.proxyUrl) {
                if (global['_vsts_task_lib_proxy']) {
                    let proxyFromEnv: VsoBaseInterfaces.IProxyConfiguration = {
                        proxyUrl: global['_vsts_task_lib_proxy_url'],
                        proxyUsername: global['_vsts_task_lib_proxy_username'],
                        proxyPassword: this._readTaskLibSecrets(global['_vsts_task_lib_proxy_password']),
                        proxyBypassHosts: JSON.parse(global['_vsts_task_lib_proxy_bypass'] || "[]"),
                    };

                    this.options.proxy = proxyFromEnv;
                }
            }
        }

        // try get cert setting from environment variable set by VSTS-Task-Lib if there is no cert setting in the options
        if (!this.options.cert) {
            if (global['_vsts_task_lib_cert']) {
                let certFromEnv: VsoBaseInterfaces.ICertConfiguration = {
                    caFile: global['_vsts_task_lib_cert_ca'],
                    certFile: global['_vsts_task_lib_cert_clientcert'],
                    keyFile: global['_vsts_task_lib_cert_key'],
                    passphrase: this._readTaskLibSecrets(global['_vsts_task_lib_cert_passphrase']),
                };

                this.options.cert = certFromEnv;
            }
        }

        // try get ignore SSL error setting from environment variable set by VSTS-Task-Lib if there is no ignore SSL error setting in the options
        if (!this.options.ignoreSslError) {
            this.options.ignoreSslError = !!global['_vsts_task_lib_skip_cert_validation'];
        }

        let userAgent: string;
        const nodeApiName: string = 'azure-devops-node-api';
        if(isBrowser) {
            if(requestSettings) {
                userAgent = `${requestSettings.productName}/${requestSettings.productVersion} (${nodeApiName}; ${window.navigator.userAgent})`
            } else {
                userAgent = `${nodeApiName} (${window.navigator.userAgent})`;
            }
        } else {
            let nodeApiVersion: string = 'unknown';
            const packageJsonPath: string = path.resolve(__dirname, 'package.json');
            if (fs.existsSync(packageJsonPath)) {
                nodeApiVersion = JSON.parse(fs.readFileSync(packageJsonPath, 'utf8')).version;
            }
            const osName: string = os.platform();
            const osVersion: string = os.release();

            if (requestSettings) {
                userAgent = `${requestSettings.productName}/${requestSettings.productVersion} (${nodeApiName} ${nodeApiVersion}; ${osName} ${osVersion})`;
            }
            else {
                userAgent = `${nodeApiName}/${nodeApiVersion} (${osName} ${osVersion})`;
            }
        }
        this.rest = new rm.RestClient(userAgent, null, [this.authHandler], this.options);
        this.vsoClient = new vsom.VsoClient(defaultUrl, this.rest);
    }

    /**
     *  Convenience factory to create with a bearer token.
     * @param defaultServerUrl default server url to use when creating new apis from factory methods
     * @param defaultAuthHandler default authentication credentials to use when creating new apis from factory methods
     */
    public static createWithBearerToken(defaultUrl: string, token: string, options?: VsoBaseInterfaces.IRequestOptions) {
        let bearerHandler = getBearerHandler(token);
        return new this(defaultUrl, bearerHandler, options);
    }

    public async connect(): Promise<lim.ConnectionData> {
        return new Promise<lim.ConnectionData>(async (resolve, reject) => {
            try {
                let res: rm.IRestResponse<lim.ConnectionData>;
                res = await this.rest.get<lim.ConnectionData>(this.vsoClient.resolveUrl('/_apis/connectionData'));
                resolve(res.result);
            }
            catch (err) {
                reject(err);
            }
        });
    }

    /**
     * Each factory method can take a serverUrl and a list of handlers
     * if these aren't provided, the default url and auth handler given to the constructor for this class will be used
     */
    public async getBuildApi(serverUrl?: string, handlers?: VsoBaseInterfaces.IRequestHandler[]): Promise<buildm.IBuildApi> {
        serverUrl = await this._getResourceAreaUrl(serverUrl || this.serverUrl, buildm.BuildApi.RESOURCE_AREA_ID);
        handlers = handlers || [this.authHandler];
        return new buildm.BuildApi(serverUrl, handlers, this.options);
    }

    public async getCoreApi(serverUrl?: string, handlers?: VsoBaseInterfaces.IRequestHandler[]): Promise<corem.ICoreApi> {
        // TODO: Load RESOURCE_AREA_ID correctly.
        serverUrl = await this._getResourceAreaUrl(serverUrl || this.serverUrl, "79134c72-4a58-4b42-976c-04e7115f32bf");
        handlers = handlers || [this.authHandler];
        return new corem.CoreApi(serverUrl, handlers, this.options);
    }

    public async getDashboardApi(serverUrl?: string, handlers?: VsoBaseInterfaces.IRequestHandler[]): Promise<dashboardm.IDashboardApi> {
        // TODO: Load RESOURCE_AREA_ID correctly.
        serverUrl = await this._getResourceAreaUrl(serverUrl || this.serverUrl, "31c84e0a-3ece-48fd-a29d-100849af99ba");
        handlers = handlers || [this.authHandler];
        return new dashboardm.DashboardApi(serverUrl, handlers, this.options);
    }

    public async getExtensionManagementApi(serverUrl?: string, handlers?: VsoBaseInterfaces.IRequestHandler[]): Promise<extmgmtm.IExtensionManagementApi> {
        // TODO: Load RESOURCE_AREA_ID correctly.
        serverUrl = await this._getResourceAreaUrl(serverUrl || this.serverUrl, "6c2b0933-3600-42ae-bf8b-93d4f7e83594");
        handlers = handlers || [this.authHandler];
        return new extmgmtm.ExtensionManagementApi(serverUrl, handlers, this.options);
    }

    public async getFeatureManagementApi(serverUrl?: string, handlers?: VsoBaseInterfaces.IRequestHandler[]): Promise<featuremgmtm.IFeatureManagementApi> {
        // TODO: Load RESOURCE_AREA_ID correctly.
        serverUrl = await this._getResourceAreaUrl(serverUrl || this.serverUrl, "");
        handlers = handlers || [this.authHandler];
        return new featuremgmtm.FeatureManagementApi(serverUrl, handlers, this.options);
    }

    public async getFileContainerApi(serverUrl?: string, handlers?: VsoBaseInterfaces.IRequestHandler[]): Promise<filecontainerm.IFileContainerApi> {
        // TODO: Load RESOURCE_AREA_ID correctly.
        serverUrl = await this._getResourceAreaUrl(serverUrl || this.serverUrl, "");
        handlers = handlers || [this.authHandler];
        return new filecontainerm.FileContainerApi(serverUrl, handlers, this.options);
    }

    public async getGalleryApi(serverUrl?: string, handlers?: VsoBaseInterfaces.IRequestHandler[]): Promise<gallerym.IGalleryApi> {
        serverUrl = await this._getResourceAreaUrl(serverUrl || this.serverUrl, gallerym.GalleryApi.RESOURCE_AREA_ID);
        handlers = handlers || [this.authHandler];
        return new gallerym.GalleryApi(serverUrl, handlers, this.options);
    }

    public async getGitApi(serverUrl?: string, handlers?: VsoBaseInterfaces.IRequestHandler[]): Promise<gitm.IGitApi> {
        serverUrl = await this._getResourceAreaUrl(serverUrl || this.serverUrl, gitm.GitApi.RESOURCE_AREA_ID);
        handlers = handlers || [this.authHandler];
        return new gitm.GitApi(serverUrl, handlers, this.options);
    }

    // TODO: Don't call resource area here? Will cause infinite loop?
    public async getLocationsApi(serverUrl?: string, handlers?: VsoBaseInterfaces.IRequestHandler[]): Promise<locationsm.ILocationsApi> {
        let optionsClone: VsoBaseInterfaces.IRequestOptions = Object.assign({}, this.options);
        optionsClone.allowRetries = true;
        optionsClone.maxRetries = 5;
        serverUrl = await serverUrl || this.serverUrl;
        handlers = handlers || [this.authHandler];
        return new locationsm.LocationsApi(serverUrl, handlers, optionsClone);
    }

    public async getNotificationApi(serverUrl?: string, handlers?: VsoBaseInterfaces.IRequestHandler[]): Promise<notificationm.INotificationApi> {
        // TODO: Load RESOURCE_AREA_ID correctly.
        serverUrl = await this._getResourceAreaUrl(serverUrl || this.serverUrl, "");
        handlers = handlers || [this.authHandler];
        return new notificationm.NotificationApi(serverUrl, handlers, this.options);
    }

    public async getPolicyApi(serverUrl?: string, handlers?: VsoBaseInterfaces.IRequestHandler[]): Promise<policym.IPolicyApi> {
        // TODO: Load RESOURCE_AREA_ID correctly.
        serverUrl = await this._getResourceAreaUrl(serverUrl || this.serverUrl, "fb13a388-40dd-4a04-b530-013a739c72ef");
        handlers = handlers || [this.authHandler];
        return new policym.PolicyApi(serverUrl, handlers, this.options);
    }

    public async getProfileApi(serverUrl?: string, handlers?: VsoBaseInterfaces.IRequestHandler[]): Promise<profilem.IProfileApi> {
        // TODO: Load RESOURCE_AREA_ID correctly.
        serverUrl = await this._getResourceAreaUrl(serverUrl || this.serverUrl, "8ccfef3d-2b87-4e99-8ccb-66e343d2daa8");
        handlers = handlers || [this.authHandler];
        return new profilem.ProfileApi(serverUrl, handlers, this.options);
    }

    public async getProjectAnalysisApi(serverUrl?: string, handlers?: VsoBaseInterfaces.IRequestHandler[]): Promise<projectm.IProjectAnalysisApi> {
        // TODO: Load RESOURCE_AREA_ID correctly.
        serverUrl = await this._getResourceAreaUrl(serverUrl || this.serverUrl, "7658fa33-b1bf-4580-990f-fac5896773d3");
        handlers = handlers || [this.authHandler];
        return new projectm.ProjectAnalysisApi(serverUrl, handlers, this.options);
    }

    public async getSecurityRolesApi(serverUrl?: string, handlers?: VsoBaseInterfaces.IRequestHandler[]): Promise<securityrolesm.ISecurityRolesApi> {
        // TODO: Load RESOURCE_AREA_ID correctly.
        serverUrl = await this._getResourceAreaUrl(serverUrl || this.serverUrl, "");
        handlers = handlers || [this.authHandler];
        return new securityrolesm.SecurityRolesApi(serverUrl, handlers, this.options);
    }

    public async getReleaseApi(serverUrl?: string, handlers?: VsoBaseInterfaces.IRequestHandler[]): Promise<releasem.IReleaseApi> {
        // TODO: Load RESOURCE_AREA_ID correctly.
        serverUrl = await this._getResourceAreaUrl(serverUrl || this.serverUrl, "efc2f575-36ef-48e9-b672-0c6fb4a48ac5");
        handlers = handlers || [this.authHandler];
        return new releasem.ReleaseApi(serverUrl, handlers, this.options);
    }

    public async getTaskApi(serverUrl?: string, handlers?: VsoBaseInterfaces.IRequestHandler[]): Promise<taskm.ITaskApi> {
        // TODO: Load RESOURCE_AREA_ID correctly.
        serverUrl = await this._getResourceAreaUrl(serverUrl || this.serverUrl, "");
        handlers = handlers || [this.authHandler];
        return new taskm.TaskApi(serverUrl, handlers, this.options);
    }

    public async getTaskAgentApi(serverUrl?: string, handlers?: VsoBaseInterfaces.IRequestHandler[]): Promise<taskagentm.ITaskAgentApi> {
        // TODO: Load RESOURCE_AREA_ID correctly.
        serverUrl = await this._getResourceAreaUrl(serverUrl || this.serverUrl, "a85b8835-c1a1-4aac-ae97-1c3d0ba72dbd");
        handlers = handlers || [this.authHandler];
        return new taskagentm.TaskAgentApi(serverUrl, handlers, this.options);
    }

    public async getTestApi(serverUrl?: string, handlers?: VsoBaseInterfaces.IRequestHandler[]): Promise<testm.ITestApi> {
        // TODO: Load RESOURCE_AREA_ID correctly.
        serverUrl = await this._getResourceAreaUrl(serverUrl || this.serverUrl, "c2aa639c-3ccc-4740-b3b6-ce2a1e1d984e");
        handlers = handlers || [this.authHandler];
        return new testm.TestApi(serverUrl, handlers, this.options);
    }

    public async getTfvcApi(serverUrl?: string, handlers?: VsoBaseInterfaces.IRequestHandler[]): Promise<tfvcm.ITfvcApi> {
        // TODO: Load RESOURCE_AREA_ID correctly.
        serverUrl = await this._getResourceAreaUrl(serverUrl || this.serverUrl, "8aa40520-446d-40e6-89f6-9c9f9ce44c48");
        handlers = handlers || [this.authHandler];
        return new tfvcm.TfvcApi(serverUrl, handlers, this.options);
    }

    public async getWikiApi(serverUrl?: string, handlers?: VsoBaseInterfaces.IRequestHandler[]): Promise<wikim.IWikiApi> {
        // TODO: Load RESOURCE_AREA_ID correctly.
        serverUrl = await this._getResourceAreaUrl(serverUrl || this.serverUrl, "bf7d82a0-8aa5-4613-94ef-6172a5ea01f3");
        handlers = handlers || [this.authHandler];
        return new wikim.WikiApi(serverUrl, handlers, this.options);
    }

    public async getWorkApi(serverUrl?: string, handlers?: VsoBaseInterfaces.IRequestHandler[]): Promise<workm.IWorkApi> {
        // TODO: Load RESOURCE_AREA_ID correctly.
        serverUrl = await this._getResourceAreaUrl(serverUrl || this.serverUrl, "1d4f49f9-02b9-4e26-b826-2cdb6195f2a9");
        handlers = handlers || [this.authHandler];
        return new workm.WorkApi(serverUrl, handlers, this.options);
    }

    public async getWorkItemTrackingApi(serverUrl?: string, handlers?: VsoBaseInterfaces.IRequestHandler[]): Promise<workitemtrackingm.IWorkItemTrackingApi> {
        serverUrl = await this._getResourceAreaUrl(serverUrl || this.serverUrl, workitemtrackingm.WorkItemTrackingApi.RESOURCE_AREA_ID);
        handlers = handlers || [this.authHandler];
        return new workitemtrackingm.WorkItemTrackingApi(serverUrl, handlers, this.options);
    }

    public async getWorkItemTrackingProcessApi(serverUrl?: string, handlers?: VsoBaseInterfaces.IRequestHandler[]): Promise<workitemtrackingprocessm.IWorkItemTrackingProcessApi> {
        // TODO: Load RESOURCE_AREA_ID correctly.
        serverUrl = await this._getResourceAreaUrl(serverUrl || this.serverUrl, "5264459e-e5e0-4bd8-b118-0985e68a4ec5");
        handlers = handlers || [this.authHandler];
        return new workitemtrackingprocessm.WorkItemTrackingProcessApi(serverUrl, handlers, this.options);
    }

    public async getWorkItemTrackingProcessDefinitionApi(serverUrl?: string, handlers?: VsoBaseInterfaces.IRequestHandler[]): Promise<workitemtrackingprocessdefinitionm.IWorkItemTrackingProcessDefinitionsApi> {
        // TODO: Load RESOURCE_AREA_ID correctly.
        serverUrl = await this._getResourceAreaUrl(serverUrl || this.serverUrl, "5264459e-e5e0-4bd8-b118-0985e68a4ec5");
        handlers = handlers || [this.authHandler];
        return new workitemtrackingprocessdefinitionm.WorkItemTrackingProcessDefinitionsApi(serverUrl, handlers, this.options);
    }

    /**
     * Determines if the domain is exluded for proxy via the no_proxy env var
     * @param url: the server url
     */
    public isNoProxyHost = function(_url: string) {
        if (!process.env.no_proxy) {
            return false;
        }
        const noProxyDomains = (process.env.no_proxy || '')
        .split(',')
        .map(v => v.toLowerCase());
        const serverUrl = url.parse(_url).host.toLowerCase();
        // return true if the no_proxy includes the host
        return noProxyDomains.indexOf(serverUrl) !== -1;
    }

    private async _getResourceAreaUrl(serverUrl: string, resourceId: string): Promise<string> {
        if (!resourceId) {
            return serverUrl;
        }

        // This must be of type any, see comment just below.
        const resourceAreas: any = await this._getResourceAreas();

        if (resourceAreas === undefined) {
            throw new Error((`Failed to retrieve resource areas ' + 'from server: ${serverUrl}`));
        }

        // The response type differs based on whether or not there are resource areas. When we are on prem we get:
        // {"count":0,"value":null} and when we are on VSTS we get an array of resource areas.
        // Due to this strangeness the type of resourceAreas needs to be any and we need to check .count
        // When going against vsts count will be undefined. On prem it will be 0
        if (!resourceAreas || resourceAreas.length === 0 || resourceAreas.count === 0) {
            // For on prem environments we get an empty list
            return serverUrl;
        }

        for (var resourceArea of resourceAreas) {
            if (resourceArea.id.toLowerCase() === resourceId.toLowerCase()) {
                return resourceArea.locationUrl;
            }
        }

        throw new Error((`Could not find information for resource area ${resourceId} ' + 'from server: ${serverUrl}`));
    }

    private async _getResourceAreas(): Promise<lim.ResourceAreaInfo[]> {
        if (!this._resourceAreas) {
            const locationClient: locationsm.ILocationsApi = await this.getLocationsApi();
            this._resourceAreas = await locationClient.getResourceAreas();
        }

        return this._resourceAreas;
    }

    private _readTaskLibSecrets(lookupKey: string): string {
        if(isBrowser) {
            throw new Error("Browsers can't securely keep secrets");
        }
        // the lookupKey should has following format
        // base64encoded<keyFilePath>:base64encoded<encryptedContent>
        if (lookupKey && lookupKey.indexOf(':') > 0) {
            let lookupInfo: string[] = lookupKey.split(':', 2);

            // file contains encryption key
            let keyFile = new Buffer(lookupInfo[0], 'base64').toString('utf8');
            let encryptKey = new Buffer(fs.readFileSync(keyFile, 'utf8'), 'base64');

            let encryptedContent: string = new Buffer(lookupInfo[1], 'base64').toString('utf8');

            let decipher = crypto.createDecipher("aes-256-ctr", encryptKey)
            let decryptedContent = decipher.update(encryptedContent, 'hex', 'utf8')
            decryptedContent += decipher.final('utf8');

            return decryptedContent;
        }
    }
}
