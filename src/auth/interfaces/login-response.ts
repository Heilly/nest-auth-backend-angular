import { User } from "../entities/user.entity";

export interface LoginResponse {
    user: User; //uso mi entities como tipo de datos
    token: string;
}