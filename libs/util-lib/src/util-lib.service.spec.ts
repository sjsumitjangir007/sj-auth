import { Test, TestingModule } from '@nestjs/testing';
import { UtilLibService } from './util-lib.service';

describe('UtilLibService', () => {
  let service: UtilLibService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [UtilLibService],
    }).compile();

    service = module.get<UtilLibService>(UtilLibService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });
});
