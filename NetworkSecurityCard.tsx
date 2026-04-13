interface NetworkSecurityData {
    hardcoded_ips: string[];
    hardcoded_urls: string[];
    allows_cleartext_traffic: boolean;
    has_concerns: boolean;
}

const NetworkSecurityCard = ({ network }: { network: NetworkSecurityData }) => {
    return (
        <div className="bg-slate-800/50 backdrop-blur-md border border-slate-700 rounded-2xl p-6">
            <div className="flex items-center justify-between mb-4">
                <h2 className="text-xl font-semibold text-slate-300">Network Security</h2>
                {network.has_concerns && (
                    <svg className="w-6 h-6 text-orange-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                    </svg>
                )}
            </div>

            <div className="space-y-4">
                {network.allows_cleartext_traffic && (
                    <div className="bg-orange-500/10 border border-orange-500/20 rounded-xl p-3 flex items-start space-x-3">
                        <svg className="w-5 h-5 text-orange-500 mt-0.5 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                        </svg>
                        <div>
                            <p className="text-orange-300 font-medium text-sm">Cleartext Traffic Allowed</p>
                            <p className="text-orange-400/70 text-xs mt-1">App allows unencrypted network communication</p>
                        </div>
                    </div>
                )}

                {network.hardcoded_ips && network.hardcoded_ips.length > 0 && (
                    <div>
                        <p className="text-slate-400 text-sm mb-2">Hardcoded IP Addresses ({network.hardcoded_ips.length})</p>
                        <div className="bg-slate-700/30 rounded-lg p-3 space-y-1 max-h-32 overflow-y-auto">
                            {network.hardcoded_ips.map((ip, idx) => (
                                <div key={idx} className="font-mono text-xs text-cyan-400">{ip}</div>
                            ))}
                        </div>
                    </div>
                )}

                {network.hardcoded_urls && network.hardcoded_urls.length > 0 && (
                    <div>
                        <p className="text-slate-400 text-sm mb-2">Hardcoded URLs ({network.hardcoded_urls.length})</p>
                        <div className="bg-slate-700/30 rounded-lg p-3 space-y-1 max-h-32 overflow-y-auto">
                            {network.hardcoded_urls.map((url, idx) => (
                                <div key={idx} className="font-mono text-xs text-blue-400 break-all">{url}</div>
                            ))}
                        </div>
                    </div>
                )}

                {!network.has_concerns && (
                    <div className="bg-green-500/10 border border-green-500/20 rounded-xl p-3 flex items-center space-x-3">
                        <svg className="w-5 h-5 text-green-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                        </svg>
                        <p className="text-green-300 font-medium text-sm">No Network Security Concerns</p>
                    </div>
                )}
            </div>
        </div>
    );
};

export default NetworkSecurityCard;
