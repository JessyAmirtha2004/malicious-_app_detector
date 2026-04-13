interface RiskBreakdownData {
    permissions: number;
    certificate: number;
    network: number;
    code_entropy: number;
    api_misuse: number;
    threat_intel: number;
}

const RiskBreakdown = ({ breakdown, totalScore }: { breakdown: RiskBreakdownData; totalScore: number }) => {
    const getBarColor = (score: number, max: number) => {
        const percentage = (score / max) * 100;
        if (percentage >= 70) return 'bg-red-500';
        if (percentage >= 40) return 'bg-orange-500';
        if (percentage >= 20) return 'bg-yellow-500';
        return 'bg-green-500';
    };

    const factors = [
        { name: 'Permissions', score: breakdown.permissions, max: 30 },
        { name: 'Certificate', score: breakdown.certificate, max: 15 },
        { name: 'Network', score: breakdown.network, max: 15 },
        { name: 'Code & Entropy', score: breakdown.code_entropy, max: 15 },
        { name: 'API Misuse', score: breakdown.api_misuse, max: 15 },
        { name: 'Threat Intel', score: breakdown.threat_intel, max: 10 }
    ];

    return (
        <div className="bg-slate-800/50 backdrop-blur-md border border-slate-700 rounded-2xl p-6 h-full">
            <h2 className="text-xl font-semibold text-slate-300 mb-6">Risk Multi-Factor Breakdown</h2>
            <div className="space-y-5">
                {factors.map((factor, idx) => (
                    <div key={idx}>
                        <div className="flex justify-between mb-2 items-center">
                            <span className="text-slate-400 text-xs font-bold uppercase tracking-widest">{factor.name}</span>
                            <span className="text-slate-200 text-sm font-mono">{factor.score} / {factor.max}</span>
                        </div>
                        <div className="w-full bg-slate-900 rounded-full h-1.5 overflow-hidden border border-white/5">
                            <div
                                className={`h-full ${getBarColor(factor.score, factor.max)} transition-all duration-1000 ease-out rounded-full`}
                                style={{ width: `${(factor.score / factor.max) * 100}%` }}
                            />
                        </div>
                    </div>
                ))}

                <div className="pt-6 mt-6 border-t border-slate-700/50">
                    <div className="flex justify-between items-center bg-slate-900/60 p-4 rounded-2xl border border-slate-700/50 shadow-inner">
                        <span className="text-slate-400 font-medium text-sm">Aggregated Risk</span>
                        <div className="text-right">
                            <span className="text-3xl font-black text-white px-2 py-0.5 rounded-lg" style={{ textShadow: `0 0 20px ${totalScore > 50 ? 'rgba(239, 68, 68, 0.4)' : 'rgba(16, 185, 129, 0.4)'}` }}>
                                {totalScore}
                            </span>
                            <span className="text-xs text-slate-500 ml-1 font-bold">/ 100</span>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
};

export default RiskBreakdown;
