import { exec } from 'child_process'
import { readFile, unlink, writeFile } from 'fs/promises'
import { dirname } from 'path'
import * as tempy from 'tempy'
import { CERTIFICATE_PIN } from '../config'
import { InternalException } from '../types/errors'
import { logError } from './logUtils'

const execute = (command: string): Promise<string> => {
  return new Promise((resolve, reject) => {
    exec(command, (err, stdout) => {
      if (err) {
        return reject(stdout || err.message)
      } else {
        resolve(stdout)
      }
    })
  })
}

let contrainerHash: string | null = null

const getContainerHash = async () => {
  if (!contrainerHash) {
    const response = await execute('certmgr -list')
    const match = response.match(/SHA1 Hash\s*: (\w+)$/m)
    if (!match) {
      throw new InternalException('Cannot get container hash. It seems that service is not correctly configured')
    }
    contrainerHash = match[1]
  }
  return contrainerHash
}

export const cryptoProSign = async (str: string): Promise<string> => {
  const containerHash = await getContainerHash()
  try {
    const tempFile = tempy.file({ extension: 'unsigned' })
    const signedFile = tempFile + '.sgn'
    await writeFile(tempFile, str)
    const dirName = dirname(tempFile)
    // eslint-disable-next-line max-len
	const container = String.raw`\\.\HDIMAGE\IPK_NONAME`
	const cmd = `csptest -keys -cont '${container}' -password '${CERTIFICATE_PIN}' -sign GOST12_256 -in "${tempFile}" -out "${signedFile}" -keytype exchange`
    await execute(cmd)
    const result = await readFile(signedFile)
    await unlink(signedFile)
    await unlink(tempFile)
	const reversedContent = Buffer.from(result).reverse();
	return reversedContent.toString('base64url');
  } catch (e) {
    logError(`sign error ${e}`, '', 'СryptoProSign')
    throw new InternalException('Failed to create sign. It seems that service is not correctly configured')
  }
}
