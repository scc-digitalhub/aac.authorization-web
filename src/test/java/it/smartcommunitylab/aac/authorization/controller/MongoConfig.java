/**
 *    Copyright 2015 Fondazione Bruno Kessler - Trento RISE
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */

package it.smartcommunitylab.aac.authorization.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.PropertySource;
import org.springframework.data.mongodb.MongoDbFactory;
import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.data.mongodb.core.SimpleMongoDbFactory;

import com.mongodb.MongoClient;

@Configuration
@PropertySource("classpath:aac.authorization.properties")
public class MongoConfig {

	private final Logger logger = LoggerFactory.getLogger(MongoConfig.class);

	@Value("${mongo.host: 127.0.0.1 }")
	private String dbHostConf;

	@Value("${mongo.port: 27017 }")
	private int dbPortConf;

	@Value("${mongo.db_name: 'aac-authorization-db' }")
	private String dbNameConf;

	public @Bean MongoTemplate mongoTemplate() throws Exception {
		MongoClient mongoClient = new MongoClient(dbHostConf, dbPortConf);
		MongoDbFactory mongoDbFactory = new SimpleMongoDbFactory(mongoClient, dbNameConf);
		return new MongoTemplate(mongoDbFactory);
	}


}
