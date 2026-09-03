import { get, post } from './http'

export interface Me {
  user: { username: string; totpEnabled: boolean; selectedDomainId?: number | null }
}

export const authApi = {
  me: () => get<Me>('/auth/me'),
  setSelectedDomain: (domainId: number | null) =>
    post<{ ok: boolean; selectedDomainId: number | null }>('/auth/selected-domain', { domainId }),
  login: (username: string, password: string, token?: string) =>
    post<{ user: { username: string } }>('/auth/login', { username, password, ...(token ? { token } : {}) }),
  logout: () => post<{ ok: true }>('/auth/logout'),
  enroll: () => get<{ totpEnabled: boolean; otpauthUrl: string }>('/auth/enroll'),
  enableTotp: (token: string) => post<{ totpEnabled: boolean }>('/auth/totp/enable', { token }),
  disableTotp: (token: string) => post<{ totpEnabled: boolean }>('/auth/totp/disable', { token }),
  changePassword: (currentPassword: string, newPassword: string) =>
    post<{ ok: true }>('/auth/password', { currentPassword, newPassword }),
  changeUsername: (password: string, newUsername: string) =>
    post<{ ok: true; username: string }>('/auth/username', { password, newUsername }),
}
