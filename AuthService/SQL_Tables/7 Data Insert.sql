USE [test_db]
GO

insert into [dbo].[AccountStatus] (Status, StatusDesc) values ('Active', 'Active user')
insert into [dbo].[AccountStatus] (Status, StatusDesc) values ('Unverified', 'Unverified user')
insert into [dbo].[AccountStatus] (Status, StatusDesc) values ('Locked', 'Locked user')
insert into [dbo].[AccountStatus] (Status, StatusDesc) values ('Blocked', 'Blocked user')

GO
insert into [dbo].AccountTypes(Type, TypeDesc) values ('User', 'regular user')
insert into [dbo].AccountTypes(Type, TypeDesc) values ('Editor', 'can change account status')
insert into [dbo].AccountTypes(Type, TypeDesc) values ('Admin', 'super user')

GO
--
insert into [dbo].VerifyTypes (Type, TypeDesc) values ('Phone', 'Preferred Verification Over Phone')
insert into [dbo].VerifyTypes (Type, TypeDesc) values ('Email', 'Preferred Verification Over Email')
insert into [dbo].VerifyTypes (Type, TypeDesc) values ('Password', 'Preferred Verification Passcode')
insert into [dbo].VerifyTypes (Type, TypeDesc) values ('Other', 'Preferred Verification <other>')


DBCC CHECKIDENT ('VerifyTypes', RESEED, 0);
-- reset db

delete [dbo].VerifyCodes
delete [dbo].AccessToken
delete [dbo].AccountInfo