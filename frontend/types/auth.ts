export interface User {
  id: number;
  name: string;
  email: string;
}

export interface AuthContextType {
  user: User | null;

  loading: boolean;

  login: (
    token: string,
    user: User
  ) => void;

  logout: () => void;
}