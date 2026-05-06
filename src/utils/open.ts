import { spawn } from 'node:child_process'
import { platform } from 'node:os'

export function openInBrowser(filePath: string) {
    const p = platform()
    if (p === 'win32') {
        // start requires shell:true and the empty string is a required title arg
        spawn('cmd', ['/c', 'start', '', filePath], { stdio: 'ignore' })
    } else if (p === 'darwin') {
        spawn('open', [filePath], { stdio: 'ignore' }).unref()
    } else {
        spawn('xdg-open', [filePath], { stdio: 'ignore' }).unref()
    }
}