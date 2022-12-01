import { Module } from '@nestjs/common';
import { UtilLibService } from './util-lib.service';

@Module({
  providers: [UtilLibService],
  exports: [UtilLibService],
})
export class UtilLibModule {}
