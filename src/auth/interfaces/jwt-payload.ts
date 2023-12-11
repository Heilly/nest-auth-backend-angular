

export interface JwtPayload {
    id: string;
    iat?: number; //fecha de creacion
    exp?: number; //fecha expira
}