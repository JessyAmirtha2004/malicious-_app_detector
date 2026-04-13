interface VirusTotalData {
    positives: number;
    total: number;
    permalink: string;
    status: string;
}

interface IPReputation {
    ip: string;
    reputation_score: number;
    is_malicious: boolean;
    source: string;
}

interface ThreatIntel {
    virustotal: VirusTotalData;
    ip_reputation: IPReputation[];
    last_check: string;
}

const SecurityIntelligenceCard = ({ intel }: { intel: ThreatIntel }) => {
    return (
        <div className="bg-slate-800/50 backdrop-blur-md border border-slate-700 rounded-2xl p-6 h-full">
            <h2 className="text-xl font-semibold text-slate-300 mb-6 flex items-center">
                <svg className="w-5 h-5 mr-2 text-cyan-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.040 12.02 12.02 0 00-3.922 8.419 11.973 11.973 0 005.171 9.583c2.152 1.34 4.597 2.112 7.211 2.112s5.059-.772 7.211-2.112a11.973 11.973 0 005.171-9.583 12.02 12.02 0 00-3.922-8.419z" />
                </svg>
                Threat Intelligence
            </h2>

            {/* VirusTotal Section */}
            <div className="mb-8">
                <div className="flex items-center justify-between mb-4">
                    <h3 className="text-sm font-medium text-slate-400 uppercase tracking-wider">VirusTotal Scan</h3>
                    <span className={`px-2 py-0.5 rounded-full text-xs font-bold ${intel.virustotal.positives > 0 ? 'bg-red-500/20 text-red-400' : 'bg-green-500/20 text-green-400'}`}>
                        {intel.virustotal.status}
                    </span>
                </div>

                <div className="bg-slate-900/50 rounded-xl p-4 border border-slate-700/50">
                    <div className="flex items-center justify-between mb-2">
                        <span className="text-slate-300 text-sm">Detection Ratio</span>
                        <span className={`text-lg font-bold ${intel.virustotal.positives > 0 ? 'text-red-400' : 'text-slate-100'}`}>
                            {intel.virustotal.positives} / {intel.virustotal.total}
                        </span>
                    </div>
                    <div className="w-full bg-slate-800 rounded-full h-1.5 mb-4">
                        <div
                            className={`h-full rounded-full ${intel.virustotal.positives > 0 ? 'bg-red-500' : 'bg-green-500'}`}
                            style={{ width: `${(intel.virustotal.positives / intel.virustotal.total) * 100}%` }}
                        />
                    </div>
                    <a
                        href={intel.virustotal.permalink}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-xs text-cyan-400 hover:text-cyan-300 flex items-center transition-colors"
                    >
                        View Full Report
                        <svg className="w-3 h-3 ml-1" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14" />
                        </svg>
                    </a>
                </div>
            </div>

            {/* IP Reputation Section */}
            <div>
                <h3 className="text-sm font-medium text-slate-400 uppercase tracking-wider mb-4">OSINT IP Reputation</h3>
                <div className="space-y-3">
                    {intel.ip_reputation.length > 0 ? (
                        intel.ip_reputation.map((ip, idx) => (
                            <div key={idx} className="flex items-center justify-between p-3 bg-slate-900/30 rounded-lg border border-slate-700/30">
                                <div className="flex items-center">
                                    <div className={`w-2 h-2 rounded-full mr-3 ${ip.is_malicious ? 'bg-red-500 animate-pulse' : 'bg-green-500'}`}></div>
                                    <span className="text-slate-200 text-sm font-mono">{ip.ip}</span>
                                </div>
                                <span className="text-xs text-slate-500">{ip.source}</span>
                            </div>
                        ))
                    ) : (
                        <p className="text-slate-500 text-sm italic">No hardcoded IPs found for reputation check.</p>
                    )}
                </div>
            </div>

            <div className="mt-auto pt-6 text-[10px] text-slate-500 text-right italic">
                Last checked: {new Date(intel.last_check).toLocaleString()}
            </div>
        </div>
    );
};

export default SecurityIntelligenceCard;
