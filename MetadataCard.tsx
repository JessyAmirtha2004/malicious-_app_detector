interface MetadataData {
    app_name: string;
    package_name: string;
    version_code: string;
    version_name: string;
    min_sdk?: string;
    target_sdk?: string;
    file_size_mb?: number;
}

interface HashesData {
    md5?: string;
    sha1?: string;
    sha256?: string;
}

const MetadataCard = ({ meta, hashes }: { meta: MetadataData; hashes?: HashesData }) => {
    const copyToClipboard = (text: string) => {
        navigator.clipboard.writeText(text);
    };

    return (
        <div className="bg-slate-800/50 backdrop-blur-md border border-slate-700 rounded-2xl p-6">
            <h2 className="text-xl font-semibold text-slate-300 mb-4">App Metadata</h2>
            <div className="space-y-3">
                <div className="flex justify-between border-b border-slate-700 pb-2">
                    <span className="text-slate-400">App Name</span>
                    <span className="font-medium text-white">{meta.app_name}</span>
                </div>

                <div className="flex justify-between border-b border-slate-700 pb-2">
                    <span className="text-slate-400">Package</span>
                    <span className="font-medium text-cyan-400 truncate max-w-[200px]" title={meta.package_name}>
                        {meta.package_name}
                    </span>
                </div>

                <div className="flex justify-between border-b border-slate-700 pb-2">
                    <span className="text-slate-400">Version</span>
                    <span className="font-medium text-white">
                        {meta.version_name} ({meta.version_code})
                    </span>
                </div>

                {meta.min_sdk && (
                    <div className="flex justify-between border-b border-slate-700 pb-2">
                        <span className="text-slate-400">Min SDK</span>
                        <span className="font-medium text-white">API {meta.min_sdk}</span>
                    </div>
                )}

                {meta.target_sdk && (
                    <div className="flex justify-between border-b border-slate-700 pb-2">
                        <span className="text-slate-400">Target SDK</span>
                        <span className="font-medium text-white">API {meta.target_sdk}</span>
                    </div>
                )}

                {meta.file_size_mb && (
                    <div className="flex justify-between border-b border-slate-700 pb-2">
                        <span className="text-slate-400">File Size</span>
                        <span className="font-medium text-white">{meta.file_size_mb} MB</span>
                    </div>
                )}

                {hashes && hashes.sha256 && (
                    <div className="pt-3">
                        <p className="text-slate-400 text-sm mb-2">SHA-256 Hash</p>
                        <div
                            className="bg-slate-700/30 rounded-lg p-2 flex items-center justify-between cursor-pointer hover:bg-slate-700/50 transition-colors"
                            onClick={() => copyToClipboard(hashes.sha256!)}
                            title="Click to copy"
                        >
                            <span className="font-mono text-xs text-cyan-400 break-all">{hashes.sha256}</span>
                            <svg className="w-4 h-4 text-slate-400 ml-2 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                            </svg>
                        </div>
                    </div>
                )}
            </div>
        </div>
    );
};

export default MetadataCard;
