interface CertificateData {
    issuer: string;
    subject: string;
    is_self_signed: boolean;
    is_debug: boolean;
    is_expired: boolean;
    valid_from?: string;
    valid_to?: string;
}

const CertificateCard = ({ certificate }: { certificate: CertificateData }) => {
    const hasWarning = certificate.is_debug || certificate.is_expired || certificate.is_self_signed;

    return (
        <div className="bg-slate-800/50 backdrop-blur-md border border-slate-700 rounded-2xl p-6">
            <div className="flex items-center justify-between mb-4">
                <h2 className="text-xl font-semibold text-slate-300">Certificate Information</h2>
                {hasWarning && (
                    <svg className="w-6 h-6 text-yellow-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                    </svg>
                )}
            </div>

            <div className="space-y-3">
                <div className="border-b border-slate-700 pb-2">
                    <span className="text-slate-400 text-sm">Subject</span>
                    <p className="font-medium text-white text-sm mt-1 break-all">{certificate.subject}</p>
                </div>

                <div className="border-b border-slate-700 pb-2">
                    <span className="text-slate-400 text-sm">Issuer</span>
                    <p className="font-medium text-white text-sm mt-1 break-all">{certificate.issuer}</p>
                </div>

                {certificate.valid_from && certificate.valid_to && (
                    <div className="border-b border-slate-700 pb-2">
                        <span className="text-slate-400 text-sm">Validity Period</span>
                        <p className="font-medium text-white text-xs mt-1">
                            {new Date(certificate.valid_from).toLocaleDateString()} - {new Date(certificate.valid_to).toLocaleDateString()}
                        </p>
                    </div>
                )}

                <div className="flex flex-wrap gap-2 mt-3">
                    {certificate.is_debug && (
                        <span className="px-3 py-1 bg-red-500/20 border border-red-500/30 rounded-full text-red-300 text-xs font-medium">
                            ⚠️ Debug Certificate
                        </span>
                    )}
                    {certificate.is_self_signed && (
                        <span className="px-3 py-1 bg-yellow-500/20 border border-yellow-500/30 rounded-full text-yellow-300 text-xs font-medium">
                            Self-Signed
                        </span>
                    )}
                    {certificate.is_expired && (
                        <span className="px-3 py-1 bg-red-500/20 border border-red-500/30 rounded-full text-red-300 text-xs font-medium">
                            ⚠️ Expired
                        </span>
                    )}
                    {!hasWarning && (
                        <span className="px-3 py-1 bg-green-500/20 border border-green-500/30 rounded-full text-green-300 text-xs font-medium">
                            ✓ Valid Certificate
                        </span>
                    )}
                </div>
            </div>
        </div>
    );
};

export default CertificateCard;
