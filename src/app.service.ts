import { Injectable } from '@nestjs/common';

@Injectable()
export class AppService {
  static db: any = {};
  static session: any = {};
  getHello(): string {
    return 'Hello World!';
  }
}
