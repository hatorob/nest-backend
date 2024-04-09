
export interface JwtPayload {
    id: string;
    iat?: number;  //? fecha de creación
    exp?: number;  //? fecha de expiración
}