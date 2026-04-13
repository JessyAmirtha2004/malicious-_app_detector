import { useState } from 'react';
import CertificateCard from './components/CertificateCard';
import NetworkSecurityCard from './components/NetworkSecurityCard';
import MetadataCard from './components/MetadataCard';
import RiskBreakdown from './components/RiskBreakdown';
import CodeAnalysisCard from './components/CodeAnalysisCard';
import EntropyCard from './components/EntropyCard';
import SecurityIntelligenceCard from './components/SecurityIntelligenceCard';
import StringsApiCard from './components/StringsApiCard';

interface AnalysisData {
    meta: {
        app_name: string;
        package_name: string;
        version_code: string;
        version_name: string;
        min_sdk?: string;
        target_sdk?: string;
        file_size_mb?: number;
    };
    hashes?: {
        md5?: string;
        sha1?: string;
        sha256?: string;
    };
    permissions: string[];
    permissions_count?: number;
    dangerous_permissions: string[];
    dangerous_permissions_by_category?: Record<string, string[]>;
    certificate?: {
        issuer: string;
        subject: string;
        is_self_signed: boolean;
        is_debug: boolean;
        is_expired: boolean;
        valid_from?: string;
        valid_to?: string;
    };
    network_security?: {
        hardcoded_ips: string[];
        hardcoded_urls: string[];
        allows_cleartext_traffic: boolean;
        has_concerns: boolean;
    };
    components: {
        activities_count: number;
        services_count: number;
        receivers_count: number;
        providers_count?: number;
    };
    code_analysis?: {
        native_libraries: Record<string, string[]>;
        native_lib_count: number;
        architectures: string[];
        has_obfuscation: boolean;
        obfuscation_indicators: string[];
    };
    entropy_analysis?: {
        dex_entropies: { name: string; entropy: number }[];
        max_entropy: number;
        is_likely_packed: boolean;
        threshold: number;
    };
    strings_apis?: {
        suspicious_strings: string[];
        suspicious_string_count: number;
        high_risk_apis: string[];
        api_misuse_count: number;
    };
    threat_intel?: {
        virustotal: {
            positives: number;
            total: number;
            permalink: string;
            status: string;
        };
        ip_reputation: {
            ip: string;
            reputation_score: number;
            is_malicious: boolean;
            source: string;
        }[];
        last_check: string;
    };
    risk_score: number;
    risk_level: string;
    risk_breakdown?: {
        permissions: number;
        certificate: number;
        network: number;
        code_entropy: number;
        api_misuse: number;
        threat_intel: number;
    };
}

const AnalysisResult = ({ data }: { data: AnalysisData }) => {
    const [activeTab, setActiveTab] = useState('overview');

    const riskColor =
        data.risk_level === 'Safe' ? '#10B981' :
            data.risk_level === 'Low' ? '#3B82F6' :
                data.risk_level === 'Medium' ? '#F59E0B' :
                    data.risk_level === 'High' ? '#F97316' :
                        '#EF4444'; // Critical



    const tabs = [
        { id: 'overview', label: 'Overview', icon: 'M4 6h16M4 10h16M4 14h16M4 18h16' },
        { id: 'permissions', label: 'Permissions', icon: 'M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.040 12.02 12.02 0 00-3.922 8.419 11.973 11.973 0 005.171 9.583c2.152 1.34 4.597 2.112 7.211 2.112s5.059-.772 7.211-2.112a11.973 11.973 0 005.171-9.583 12.02 12.02 0 00-3.922-8.419z' },
        { id: 'security', label: 'Security & Intel', icon: 'M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z' },
        { id: 'code', label: 'Code Analysis', icon: 'M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4' },
        { id: 'components', label: 'Components', icon: 'M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10' }
    ];

    return (
        <div className="w-full max-w-7xl mx-auto px-4 py-8 animate-fade-in">
            {/* Header Section */}
            <div className="flex flex-col md:flex-row justify-between items-start md:items-center mb-10 gap-6 bg-slate-800/20 p-6 rounded-3xl border border-slate-700/30 backdrop-blur-sm">
                <div className="flex items-center space-x-5">
                    <div className="w-16 h-16 bg-gradient-to-br from-cyan-500 to-blue-600 rounded-2xl flex items-center justify-center shadow-lg shadow-cyan-500/20">
                        <span className="text-2xl font-bold text-white uppercase">{data.meta.app_name.substring(0, 2)}</span>
                    </div>
                    <div>
                        <h1 className="text-3xl font-bold text-white tracking-tight">{data.meta.app_name}</h1>
                        <p className="text-slate-400 font-mono text-sm">{data.meta.package_name}</p>
                    </div>
                </div>

                <div className="flex items-center space-x-6 bg-slate-900/50 px-6 py-4 rounded-2xl border border-slate-700/50">
                    <div className="text-center">
                        <div className="text-xs text-slate-500 uppercase tracking-widest mb-1">Risk Score</div>
                        <div className="text-2xl font-black" style={{ color: riskColor }}>{data.risk_score}%</div>
                    </div>
                    <div className="w-px h-10 bg-slate-700"></div>
                    <div className="text-center">
                        <div className="text-xs text-slate-500 uppercase tracking-widest mb-1">Status</div>
                        <div className="text-lg font-bold text-white leading-none">{data.risk_level.toUpperCase()}</div>
                    </div>
                </div>
            </div>

            {/* Navigation Tabs */}
            <div className="flex flex-wrap gap-2 mb-8 bg-slate-800/40 p-1.5 rounded-2xl border border-slate-700/50 w-fit mx-auto md:mx-0">
                {tabs.map((tab) => (
                    <button
                        key={tab.id}
                        onClick={() => setActiveTab(tab.id)}
                        className={`flex items-center px-5 py-2.5 rounded-xl text-sm font-medium transition-all duration-300 ${activeTab === tab.id
                            ? 'bg-cyan-500 text-white shadow-lg shadow-cyan-500/20 scale-105'
                            : 'text-slate-400 hover:text-slate-200 hover:bg-slate-700/50'
                            }`}
                    >
                        <svg className="w-4 h-4 mr-2" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d={tab.icon} />
                        </svg>
                        {tab.label}
                    </button>
                ))}
            </div>

            {/* Tab Content */}
            <div className="transition-all duration-500">
                {activeTab === 'overview' && (
                    <div className="grid grid-cols-1 lg:grid-cols-3 gap-8 animate-fade-in-up">
                        <div className="lg:col-span-2 space-y-8">
                            <MetadataCard meta={data.meta} hashes={data.hashes} />
                            <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
                                {data.strings_apis && <StringsApiCard data={data.strings_apis} />}
                                {data.entropy_analysis && <EntropyCard analysis={data.entropy_analysis} />}
                            </div>
                        </div>
                        <div className="space-y-8">
                            {data.risk_breakdown && (
                                <RiskBreakdown
                                    breakdown={data.risk_breakdown}
                                    totalScore={data.risk_score}
                                />
                            )}
                            {data.threat_intel && <SecurityIntelligenceCard intel={data.threat_intel} />}
                        </div>
                    </div>
                )}

                {activeTab === 'permissions' && (
                    <div className="animate-fade-in-up space-y-8">
                        <div className="bg-slate-800/50 border border-slate-700 rounded-2xl p-8 backdrop-blur-md">
                            <h3 className="text-2xl font-bold text-white mb-6 flex items-center">
                                <span className="w-2 h-8 bg-cyan-500 rounded-full mr-4"></span>
                                Permission Breakdown
                                <span className="ml-4 text-slate-400 text-base font-normal">
                                    ({data.dangerous_permissions.length} dangerous / {data.permissions.length} total)
                                </span>
                            </h3>

                            {data.dangerous_permissions_by_category && Object.keys(data.dangerous_permissions_by_category).length > 0 && (
                                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                                    {Object.entries(data.dangerous_permissions_by_category).map(([category, perms]) => (
                                        <div key={category} className="bg-slate-900/50 border border-slate-700/50 rounded-2xl p-5 hover:border-red-500/30 transition-colors">
                                            <div className="flex items-center justify-between mb-4 pb-3 border-b border-slate-800">
                                                <span className="text-red-400 font-bold capitalize text-lg tracking-wide">{category.replace('_', ' ')}</span>
                                                <span className="bg-red-500/20 text-red-400 px-2.5 py-1 rounded-lg text-xs font-black uppercase tracking-widest">{perms.length} FOUND</span>
                                            </div>
                                            <div className="flex flex-wrap gap-2">
                                                {perms.map((perm, idx) => (
                                                    <span key={idx} className="text-[11px] font-mono text-red-200/80 bg-red-500/10 px-2 py-1.5 rounded-md border border-red-500/10">
                                                        {perm.split('.').pop()}
                                                    </span>
                                                ))}
                                            </div>
                                        </div>
                                    ))}
                                </div>
                            )}
                        </div>
                    </div>
                )}

                {activeTab === 'security' && (
                    <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 animate-fade-in-up">
                        {data.threat_intel && <SecurityIntelligenceCard intel={data.threat_intel} />}
                        {data.network_security && <NetworkSecurityCard network={data.network_security} />}
                        {data.certificate && <CertificateCard certificate={data.certificate} />}
                    </div>
                )}

                {activeTab === 'code' && (
                    <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 animate-fade-in-up">
                        {data.code_analysis && <CodeAnalysisCard code={data.code_analysis} />}
                        {data.entropy_analysis && <EntropyCard analysis={data.entropy_analysis} />}
                        {data.strings_apis && <div className="lg:col-span-2"><StringsApiCard data={data.strings_apis} /></div>}
                    </div>
                )}

                {activeTab === 'components' && (
                    <div className="animate-fade-in-up space-y-8">
                        <div className="bg-slate-800/50 backdrop-blur-md border border-slate-700 rounded-3xl p-8">
                            <h2 className="text-2xl font-bold text-white mb-8">System Components Architecture</h2>
                            <div className="grid grid-cols-2 md:grid-cols-4 gap-6">
                                {[
                                    { label: 'Activities', count: data.components.activities_count, color: 'text-cyan-400', bg: 'bg-cyan-400/10' },
                                    { label: 'Services', count: data.components.services_count, color: 'text-purple-400', bg: 'bg-purple-400/10' },
                                    { label: 'Receivers', count: data.components.receivers_count, color: 'text-pink-400', bg: 'bg-pink-400/10' },
                                    { label: 'Providers', count: data.components.providers_count || 0, color: 'text-orange-400', bg: 'bg-orange-400/10' }
                                ].map((item, idx) => (
                                    <div key={idx} className={`${item.bg} rounded-3xl p-6 text-center border border-white/5 shadow-xl`}>
                                        <div className={`text-5xl font-black ${item.color} mb-2`}>{item.count}</div>
                                        <div className="text-slate-400 text-sm font-semibold uppercase tracking-widest">{item.label}</div>
                                    </div>
                                ))}
                            </div>
                        </div>
                    </div>
                )}
            </div>
        </div>
    );
};

export default AnalysisResult;
