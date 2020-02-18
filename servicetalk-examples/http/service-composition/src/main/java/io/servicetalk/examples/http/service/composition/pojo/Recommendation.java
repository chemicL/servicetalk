/*
 * Copyright © 2018 Apple Inc. and the ServiceTalk project authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.servicetalk.examples.http.service.composition.pojo;

public final class Recommendation {

    private String entityId;
    private String recommendedBy;

    public Recommendation() {
    }

    public Recommendation(String entityId, String recommendedBy) {
        this.entityId = entityId;
        this.recommendedBy = recommendedBy;
    }

    public void setEntityId(final String entityId) {
        this.entityId = entityId;
    }

    public void setRecommendedBy(final String recommendedBy) {
        this.recommendedBy = recommendedBy;
    }

    public String getEntityId() {
        return entityId;
    }

    public String getRecommendedBy() {
        return recommendedBy;
    }
}