/*
 * *****************************************************************************
 *      Cloud Foundry
 *      Copyright (c) [2009-2015] Pivotal Software, Inc. All Rights Reserved.
 *      This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *      You may not use this product except in compliance with the License.
 *
 *      This product includes a number of subcomponents with
 *      separate copyright notices and license terms. Your use of these
 *      subcomponents is subject to the terms and conditions of the
 *      subcomponent's license, as noted in the LICENSE file.
 * *****************************************************************************
 */

package org.cloudfoundry.identity.uaa.login.saml;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.authentication.Origin;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityProvider;
import org.cloudfoundry.identity.uaa.zone.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneProvisioning;
import org.opensaml.saml2.metadata.EntitiesDescriptor;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.RoleDescriptor;
import org.opensaml.saml2.metadata.provider.MetadataFilter;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.saml2.metadata.provider.ObservableMetadataProvider;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.security.x509.PKIXValidationInformationResolver;
import org.opensaml.xml.signature.SignatureTrustEngine;
import org.springframework.beans.factory.DisposableBean;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.saml.key.KeyManager;
import org.springframework.security.saml.metadata.ExtendedMetadata;
import org.springframework.security.saml.metadata.ExtendedMetadataDelegate;
import org.springframework.security.saml.metadata.ExtendedMetadataProvider;
import org.springframework.security.saml.metadata.MetadataManager;
import org.springframework.security.saml.trust.httpclient.TLSProtocolConfigurer;

import javax.xml.namespace.QName;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

public class ZoneAwareMetadataManager extends MetadataManager implements ExtendedMetadataProvider, InitializingBean, DisposableBean {

    private static final Log logger = LogFactory.getLog(ZoneAwareMetadataManager.class);
    private IdentityProviderProvisioning providerDao;
    private IdentityZoneProvisioning zoneDao;
    private IdentityProviderConfigurator configurator;


    public ZoneAwareMetadataManager(IdentityProviderProvisioning providerDao,
                                    IdentityZoneProvisioning zoneDao,
                                    IdentityProviderConfigurator configurator,
                                    KeyManager keyManager) throws MetadataProviderException {
        super(Collections.<MetadataProvider>emptyList());
        this.providerDao = providerDao;
        this.zoneDao = zoneDao;
        this.configurator = configurator;
        setKeyManager(keyManager);
        readAllProviders();
    }

    protected void readAllProviders() throws MetadataProviderException {
        List<IdentityProviderDefinition> definitions = new LinkedList<>();
        for (IdentityZone zone : zoneDao.retrieveAll()) {
            for (IdentityProvider provider : providerDao.retrieveAll(zone.getId())) {
                if (Origin.SAML.equals(provider.getType())) {
                    try {
                        definitions.add(JsonUtils.readValue(provider.getConfig(), IdentityProviderDefinition.class));

                    } catch (JsonUtils.JsonUtilException x) {
                        logger.error("Unable to load provider:"+provider, x);
                    }
                }
            }
        }
        configurator.refreshProviders(definitions);
        //if i specify the type here it wont let me compile
        List yup = configurator.getIdentityProviders();
        setProviders(yup);
    }

    @Override
    public void setProviders(List<MetadataProvider> newProviders) throws MetadataProviderException {
        super.setProviders(newProviders);
    }

    @Override
    public void refreshMetadata() {
        super.refreshMetadata();
    }

    @Override
    public void addMetadataProvider(MetadataProvider newProvider) throws MetadataProviderException {
        super.addMetadataProvider(newProvider);
    }

    @Override
    public void removeMetadataProvider(MetadataProvider provider) {
        super.removeMetadataProvider(provider);
    }

    @Override
    public List<MetadataProvider> getProviders() {
        return super.getProviders();
    }

    @Override
    public List<ExtendedMetadataDelegate> getAvailableProviders() {
        return super.getAvailableProviders();
    }

    @Override
    protected void initializeProvider(ExtendedMetadataDelegate provider) throws MetadataProviderException {
        super.initializeProvider(provider);
    }

    @Override
    protected void initializeProviderData(ExtendedMetadataDelegate provider) throws MetadataProviderException {
        super.initializeProviderData(provider);
    }

    @Override
    protected void initializeProviderFilters(ExtendedMetadataDelegate provider) throws MetadataProviderException {
        super.initializeProviderFilters(provider);
    }

    @Override
    protected SignatureTrustEngine getTrustEngine(MetadataProvider provider) {
        return super.getTrustEngine(provider);
    }

    @Override
    protected PKIXValidationInformationResolver getPKIXResolver(MetadataProvider provider, Set<String> trustedKeys, Set<String> trustedNames) {
        return super.getPKIXResolver(provider, trustedKeys, trustedNames);
    }

    @Override
    protected List<String> parseProvider(MetadataProvider provider) throws MetadataProviderException {
        return super.parseProvider(provider);
    }

    @Override
    public Set<String> getIDPEntityNames() {
        return super.getIDPEntityNames();
    }

    @Override
    public Set<String> getSPEntityNames() {
        return super.getSPEntityNames();
    }

    @Override
    public boolean isIDPValid(String idpID) {
        return super.isIDPValid(idpID);
    }

    @Override
    public boolean isSPValid(String spID) {
        return super.isSPValid(spID);
    }

    @Override
    public String getHostedSPName() {
        return super.getHostedSPName();
    }

    @Override
    public void setHostedSPName(String hostedSPName) {
        super.setHostedSPName(hostedSPName);
    }

    @Override
    public String getDefaultIDP() throws MetadataProviderException {
        return super.getDefaultIDP();
    }

    @Override
    public void setDefaultIDP(String defaultIDP) {
        super.setDefaultIDP(defaultIDP);
    }

    @Override
    public EntityDescriptor getEntityDescriptor(byte[] hash) throws MetadataProviderException {
        return super.getEntityDescriptor(hash);
    }

    @Override
    public String getEntityIdForAlias(String entityAlias) throws MetadataProviderException {
        return super.getEntityIdForAlias(entityAlias);
    }

    @Override
    public ExtendedMetadata getDefaultExtendedMetadata() {
        return super.getDefaultExtendedMetadata();
    }

    @Override
    public void setDefaultExtendedMetadata(ExtendedMetadata defaultExtendedMetadata) {
        super.setDefaultExtendedMetadata(defaultExtendedMetadata);
    }

    @Override
    public boolean isRefreshRequired() {
        return super.isRefreshRequired();
    }

    @Override
    public void setRefreshRequired(boolean refreshRequired) {
        super.setRefreshRequired(refreshRequired);
    }

    @Override
    public void setRefreshCheckInterval(long refreshCheckInterval) {
        super.setRefreshCheckInterval(refreshCheckInterval);
    }

    @Override
    public void setKeyManager(KeyManager keyManager) {
        super.setKeyManager(keyManager);
    }

    @Override
    public void setTLSConfigurer(TLSProtocolConfigurer configurer) {
        super.setTLSConfigurer(configurer);
    }

    @Override
    protected void doAddMetadataProvider(MetadataProvider provider, List<MetadataProvider> providerList) {
        super.doAddMetadataProvider(provider, providerList);
    }

    @Override
    public void setRequireValidMetadata(boolean requireValidMetadata) {
        super.setRequireValidMetadata(requireValidMetadata);
    }

    @Override
    public MetadataFilter getMetadataFilter() {
        return super.getMetadataFilter();
    }

    @Override
    public void setMetadataFilter(MetadataFilter newFilter) throws MetadataProviderException {
        super.setMetadataFilter(newFilter);
    }

    @Override
    public XMLObject getMetadata() throws MetadataProviderException {
        return super.getMetadata();
    }

    @Override
    public EntitiesDescriptor getEntitiesDescriptor(String name) throws MetadataProviderException {
        return super.getEntitiesDescriptor(name);
    }

    @Override
    public EntityDescriptor getEntityDescriptor(String entityID) throws MetadataProviderException {
        return super.getEntityDescriptor(entityID);
    }

    @Override
    public List<RoleDescriptor> getRole(String entityID, QName roleName) throws MetadataProviderException {
        return super.getRole(entityID, roleName);
    }

    @Override
    public RoleDescriptor getRole(String entityID, QName roleName, String supportedProtocol) throws MetadataProviderException {
        return super.getRole(entityID, roleName, supportedProtocol);
    }

    @Override
    public List<Observer> getObservers() {
        return super.getObservers();
    }

    @Override
    protected void emitChangeEvent() {
        super.emitChangeEvent();
    }

    @Override
    public boolean requireValidMetadata() {
        return super.requireValidMetadata();
    }

    @Override
    public void destroy() {

    }

    @Override
    public ExtendedMetadata getExtendedMetadata(String entityID) throws MetadataProviderException {
        return super.getExtendedMetadata(entityID);
    }

}
